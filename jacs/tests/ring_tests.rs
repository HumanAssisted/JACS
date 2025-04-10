mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use jacs::crypt::aes_encrypt::decrypt_private_key;
use secrecy::ExposeSecret;
use std::env;
use std::fs;
use utils::load_test_agent_one;

fn set_enc_to_ring() {
    unsafe {
        env::set_var(
            "JACS_AGENT_PRIVATE_KEY_FILENAME",
            "test-ring-Ed25519-private.pem",
        );
        env::set_var(
            "JACS_AGENT_PUBLIC_KEY_FILENAME",
            "test-ring-Ed25519-public.pem",
        );
        env::set_var("JACS_AGENT_KEY_ALGORITHM", "ring-Ed25519");
    }
}

#[test]
#[ignore]
fn test_ring_Ed25519_create() {
    set_enc_to_ring();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    let json_data = fs::read_to_string("tests/fixtures/raw/myagent.new.json").expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);
    set_enc_to_ring();
    // does this modify the agent sig?
    agent.generate_keys().expect("Reason");
}

#[test]
fn test_ring_Ed25519_create_and_verify_signature() {
    set_enc_to_ring();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    let json_data = fs::read_to_string("tests/fixtures/raw/myagent.new.json").expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);
    let private = agent.get_private_key().unwrap();
    let public = agent.get_public_key().unwrap();

    let binding = agent.get_private_key().unwrap();
    let borrowed_key = binding.expose_secret();
    let key_vec = decrypt_private_key(borrowed_key).expect("Failed to decrypt key");

    println!(
        "loaded keys {} {} ",
        std::str::from_utf8(&key_vec).expect("Failed to convert bytes to string"),
        std::str::from_utf8(&public).expect("Failed to convert bytes to string")
    );
}
