use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use reqwest::Client;
use secrecy::ExposeSecret;
use std::env;
use std::fs;
use tokio::runtime::Runtime; // Import the Tokio runtime

fn set_enc_to_ring() {
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

#[test]
#[ignore]
fn test_ring_ed25519_create() {
    set_enc_to_ring();
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let json_data = fs::read_to_string("examples/raw/myagent.new.json")
        .expect("Unable to read agent JSON data");
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
    )
    .expect("Failed to create a new agent");
    let _result = agent.create_agent_and_load(&json_data);
    set_enc_to_ring();
    // does this modify the agent sig?
    agent.generate_keys().expect("Failed to generate keys");
}

#[test]
fn test_ring_ed25519_create_and_verify_signature() {
    let rt = Runtime::new().expect("Failed to create Tokio runtime"); // Create a new Tokio runtime

    // Start the mock server to serve the schema files
    let mock_server = MockServer::start();

    // Setup schema mocks
    mock_server.mock(|when, then| {
        when.method(GET).path("/myagent.new.json");
        then.status(200)
            .body_from_file("examples/raw/myagent.new.json");
    });

    set_enc_to_ring();
    // Create a reqwest client instance with SSL verification disabled
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create reqwest client with disabled SSL verification");

    let header_schema_url = mock_server
        .url("/schemas/header/v1/header.schema.json")
        .to_string();
    let document_schema_url = mock_server
        .url("/schemas/document/v1/document.schema.json")
        .to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();

    // Use the Tokio runtime to block on the asynchronous code
    let json_data = rt.block_on(async {
        client
            .get(mock_server.url("/myagent.new.json"))
            .send()
            .await
            .expect("Failed to fetch agent JSON data")
            .text()
            .await
            .expect("Failed to read agent JSON data")
    });

    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        header_schema_url,
        document_schema_url,
    )
    .expect("Failed to create a new agent");
    let _result = agent.create_agent_and_load(&json_data);
    if let Some(private_key) = agent.get_private_key().ok() {
        let public_key = agent.get_public_key().expect("Public key must be present");

        let binding = private_key;
        let borrowed_key = binding.expose_secret();
        let key_vec = borrowed_key.use_secret();

        println!(
            "loaded keys {} {} ",
            std::str::from_utf8(&key_vec).expect("Failed to convert private key bytes to string"),
            std::str::from_utf8(&public_key).expect("Failed to convert public key bytes to string")
        );
    } else {
        panic!("Private key is not set");
    }
}
