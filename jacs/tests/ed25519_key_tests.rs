use secrecy::ExposeSecret;
mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use utils::load_test_agent_one;

#[test]
fn test_ed25519_fixture_key_material_and_signature_roundtrip() {
    let mut agent = load_test_agent_one();
    let public = agent.get_public_key().unwrap();
    let private = agent.get_private_key().unwrap();

    // Assert private key decryption succeeds and produces non-empty bytes
    assert!(
        !private.expose_secret().is_empty(),
        "Private key material should be non-empty"
    );

    // Assert public key is non-empty
    assert!(!public.is_empty(), "Public key should be non-empty");

    let document = agent
        .create_document_and_load(r#"{"message":"ed25519 key fixture roundtrip"}"#, None, None)
        .expect("Ed25519 fixture should sign a document");
    let document_key = document.getkey();
    agent
        .verify_document_signature(&document_key, None, None, None, None)
        .expect("Ed25519 fixture signature should verify");
}
