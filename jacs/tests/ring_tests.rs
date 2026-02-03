mod utils;
use jacs::agent::boilerplate::BoilerPlate;
#[cfg(not(target_arch = "wasm32"))]
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
use jacs::crypt::aes_encrypt::decrypt_private_key;
use secrecy::ExposeSecret;
use utils::{create_ring_test_agent, read_new_agent_fixture};

#[test]
#[ignore]
fn test_ring_Ed25519_create() {
    let mut agent = create_ring_test_agent().expect("Failed to create ring test agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
    let _result = agent.create_agent_and_load(&json_data, false, None);
    // does this modify the agent sig?
    agent.generate_keys().expect("Reason");
}

#[test]
fn test_ring_Ed25519_create_and_verify_signature() {
    let mut agent = create_ring_test_agent().expect("Failed to create ring test agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
    let _result = agent.create_agent_and_load(&json_data, false, None);

    // Explicitly load keys before trying to access them
    #[cfg(not(target_arch = "wasm32"))]
    agent.fs_load_keys().expect("Failed to load keys");

    let _private = agent.get_private_key().unwrap();
    let public = agent.get_public_key().unwrap();

    let binding = agent.get_private_key().unwrap();
    let borrowed_key = binding.expose_secret();
    let key_vec = decrypt_private_key(borrowed_key).expect("Failed to decrypt key");

    // Assert private and public keys are non-empty
    assert!(
        !key_vec.is_empty(),
        "Decrypted private key should be non-empty"
    );
    assert!(!public.is_empty(), "Public key should be non-empty");

    // Assert Ed25519 public key length (32 bytes)
    assert_eq!(
        public.len(),
        32,
        "Ed25519 public key should be 32 bytes, got {}",
        public.len()
    );
}
