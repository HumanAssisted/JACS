use jacs::agent::loaders::FileLoader;
use secrecy::ExposeSecret;
use std::env;
mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use utils::load_test_agent_one;

fn set_enc_to_rsa() {
    env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "rsa_pss_private.pem");
    env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "rsa_pss_public.pem");
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
}

#[test]
#[ignore]
fn test_rsa_create() {
    set_enc_to_rsa();
    let header_schema_url = "mock_header_schema_url";
    let document_schema_url = "mock_document_schema_url";
    let mut agent = load_test_agent_one(header_schema_url, document_schema_url)
        .expect("Failed to load test agent");
    agent.generate_keys().expect("Failed to generate keys");
}

#[test]
#[ignore]
fn test_rsa_save_encrypted() {
    set_enc_to_rsa();
    let header_schema_url = "mock_header_schema_url";
    let document_schema_url = "mock_document_schema_url";
    let mut agent = load_test_agent_one(header_schema_url, document_schema_url)
        .expect("Failed to load test agent");
    agent.fs_save_keys().expect("Failed to save keys");
}

#[test]
fn test_rsa_create_and_verify_signature() {
    set_enc_to_rsa();
    let header_schema_url = "mock_header_schema_url";
    let document_schema_url = "mock_document_schema_url";
    let agent = load_test_agent_one(header_schema_url, document_schema_url)
        .expect("Failed to load test agent");
    let _private_key = agent.get_private_key().expect("Failed to get private key");
    let public_key = agent.get_public_key().expect("Failed to get public key");

    let binding = agent
        .get_private_key()
        .expect("Failed to get binding for private key");
    let borrowed_key = binding.expose_secret();
    let key_vec = borrowed_key.use_secret();

    println!(
        "loaded keys {} {} ",
        std::str::from_utf8(&key_vec).expect("Failed to convert private key bytes to string"),
        std::str::from_utf8(&public_key).expect("Failed to convert public key bytes to string")
    );

    // Uncomment and update the following code block if signature creation and verification is needed
    // let input_str = "JACS is JACKED";
    // let file_path = "./tests/scratch/";
    // let sig = jacs::crypt::rsawrapper::sign_string(file_path, input_str).expect("Failed to sign string");
    // let signature_base64 = base64::encode(sig);

    // println!("signature was {} for {}", signature_base64, input_str);

    // let verify_result = jacs::crypt::rsawrapper::verify_string(file_path, input_str, &signature_base64)
    //     .expect("Failed to verify signature");
    // assert!(verify_result, "Signature verification failed");
}
