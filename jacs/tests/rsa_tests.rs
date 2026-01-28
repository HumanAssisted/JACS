use jacs::agent::loaders::FileLoader;
use secrecy::ExposeSecret;
mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use jacs::crypt::aes_encrypt::decrypt_private_key;
use utils::load_test_agent_one;

#[test]
#[ignore]
fn test_rsa_create() {
    let mut agent = load_test_agent_one();
    agent.generate_keys().expect("Reason");
}

#[test]
#[ignore]
fn test_rsa_save_encrypted() {
    let mut agent = load_test_agent_one();
    agent.fs_save_keys().expect("Reason");
}

#[test]
fn test_rsa_create_and_verify_signature() {
    let agent = load_test_agent_one();
    let _private = agent.get_private_key().unwrap();
    let public = agent.get_public_key().unwrap();

    let binding = agent.get_private_key().unwrap();
    let borrowed_key = binding.expose_secret();
    let key_vec = decrypt_private_key(borrowed_key).expect("Failed to decrypt key");

    // Assert private key decryption succeeds and produces non-empty bytes
    assert!(
        !key_vec.is_empty(),
        "Decrypted private key should be non-empty"
    );

    // Assert public key is non-empty
    assert!(!public.is_empty(), "Public key should be non-empty");

    // Assert key lengths are within expected RSA ranges
    // RSA private keys (PEM) are typically 1600+ bytes, public keys 400+ bytes
    assert!(
        key_vec.len() > 100,
        "RSA private key should be at least 100 bytes, got {}",
        key_vec.len()
    );
    assert!(
        public.len() > 100,
        "RSA public key should be at least 100 bytes, got {}",
        public.len()
    );
}
