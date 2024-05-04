use jacs::agent::Agent;
use jacs::schema::Schema;
use secrecy::{ExposeSecret, Zeroize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Mock function to create a test Agent with default values
pub fn mock_test_agent() -> Result<Agent, Box<dyn Error>> {
    // Mock parameters for Schema::new
    let agent_version = "mock_version".to_string();
    let header_version = "mock_version".to_string();
    let signature_version = "mock_version".to_string();

    // Create a new Schema with mock parameters
    let schema = Schema::new(&agent_version, &header_version, &signature_version)?;

    let document_schemas_map = Arc::new(Mutex::new(HashMap::<String, Schema>::new()));
    let document_map = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
    let default_directory = PathBuf::new(); // Assuming tests do not rely on a specific path

    // Mock values for Agent fields
    let public_key = vec![0u8; 32]; // Mock public key
    let private_key = vec![0u8; 32]; // Mock private key
    let key_algorithm = "mock_algorithm".to_string();

    // Use the Agent's constructor to create a new instance
    let mut agent = Agent::new(&agent_version, &header_version, &signature_version)?;

    // Set the keys using the Agent's set_keys method
    agent.set_keys(private_key, public_key, &key_algorithm)?;

    Ok(agent)
}

/// A mock PrivateKey struct for testing purposes.
pub struct MockPrivateKey {
    // This struct can contain mock fields if necessary
    dummy_field: u8, // Dummy field to satisfy Zeroize trait
}

impl Default for MockPrivateKey {
    fn default() -> Self {
        MockPrivateKey {
            // Initialize with default values
            dummy_field: 0, // Default value for the dummy field
        }
    }
}

impl Zeroize for MockPrivateKey {
    fn zeroize(&mut self) {
        // Zeroize the dummy field
        self.dummy_field = 0;
    }
}

impl ExposeSecret<String> for MockPrivateKey {
    fn expose_secret(&self) -> &String {
        // This is a placeholder to satisfy the trait.
        // In a real scenario, you would return a reference to the secret data.
        // For this mock, we'll just return a reference to a dummy string.
        static DUMMY_SECRET: String = String::new();
        &DUMMY_SECRET
    }
}
