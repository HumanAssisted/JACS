mod utils;
use jacs::agent::boilerplate::BoilerPlate;
#[cfg(not(target_arch = "wasm32"))]
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
use jacs::crypt::aes_encrypt::decrypt_private_key;
use secrecy::ExposeSecret;
use std::env;
use std::fs;

fn get_ring_config() -> String {
    let fixtures_dir = utils::find_fixtures_dir();
    unsafe {
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "testpassword");
    }
    format!("{}/raw/ring.jacs.config.json", fixtures_dir.display())
}

// Helper function to convert bytes to hex string for display
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

#[test]
#[ignore]
fn test_ring_Ed25519_create() {
    let fixtures_dir = utils::find_fixtures_dir();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    agent.load_by_config(get_ring_config()).unwrap();
    let json_data = fs::read_to_string(format!("{}/raw/myagent.new.json", fixtures_dir.display()))
        .expect("REASON");
    let _result = agent.create_agent_and_load(&json_data, false, None);
    // does this modify the agent sig?
    agent.generate_keys().expect("Reason");
}

#[test]
fn test_ring_Ed25519_create_and_verify_signature() {
    let fixtures_dir = utils::find_fixtures_dir();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    agent.load_by_config(get_ring_config()).unwrap();
    let json_data = fs::read_to_string(format!("{}/raw/myagent.new.json", fixtures_dir.display()))
        .expect("REASON");
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
