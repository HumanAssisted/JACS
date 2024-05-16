use jacs::crypt::KeyManager;
use std::env;
use std::io::{self, Write};
use std::time::{Duration, Instant};

fn set_enc_to_pq() {
    env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "test-pq-private.pem");
    env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "test-pq-public.pem");
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq-dilithium");
}

#[test]
fn test_pq_key_generation() {
    println!("Starting test_pq_key_generation");
    io::stdout().flush().unwrap();
    println!("Setting environment variables for PQ key generation");
    set_enc_to_pq();
    // Print out the environment variables for diagnostic purposes
    println!(
        "JACS_AGENT_PRIVATE_KEY_FILENAME: {:?}",
        env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap()
    );
    println!(
        "JACS_AGENT_PUBLIC_KEY_FILENAME: {:?}",
        env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap()
    );
    println!(
        "JACS_AGENT_KEY_ALGORITHM: {:?}",
        env::var("JACS_AGENT_KEY_ALGORITHM").unwrap()
    );
    println!("Environment variables set");
    io::stdout().flush().unwrap();
    println!("Creating Agent instance for key generation test");
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
    )
    .unwrap();
    println!("Agent instance created for key generation test");
    println!("Generating keys for key generation test");
    io::stdout().flush().unwrap();
    // Adding print statements before and after the generate_keys call
    println!("Before calling agent.generate_keys()");
    io::stdout().flush().unwrap();
    let start = Instant::now();
    let result = agent.generate_keys();
    let duration = start.elapsed();
    println!(
        "After calling agent.generate_keys(), Duration: {:?}",
        duration
    );
    // Print out the result of the key generation for diagnostic purposes
    match &result {
        Ok(_) => {
            println!("Keys generated successfully.");
        }
        Err(e) => println!("Key generation error: {:?}", e),
    }
    io::stdout().flush().unwrap();
    // Check if the key generation took too long
    if duration > Duration::from_secs(10) {
        panic!("Key generation took too long: {:?}", duration);
    }
    assert!(
        result.is_ok(),
        "Failed to generate keys for key generation test"
    );
    println!("Keys generated for key generation test");
    io::stdout().flush().unwrap();
    println!("Test for key generation completed successfully");
    io::stdout().flush().unwrap();
}

#[test]
fn test_pq_create_and_verify_signature() {
    // ... existing test code remains unchanged ...
}
