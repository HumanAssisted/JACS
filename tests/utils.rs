use jacs::agent::Agent;
use jacs::schema::Schema;
use secrecy::{ExposeSecret, Zeroize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Mock function to create a test Agent with default values
pub fn mock_test_agent(
    header_schema_url: &str,
    document_schema_url: &str,
) -> Result<Agent, Box<dyn Error>> {
    // Create a new Schema with mock parameters
    let _schema = Schema::new(header_schema_url, document_schema_url)?;

    let _document_schemas_map = Arc::new(Mutex::new(HashMap::<String, Schema>::new()));
    let _document_map = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
    let _default_directory = PathBuf::new(); // Assuming tests do not rely on a specific path

    // Mock values for Agent fields
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();

    // Use the Agent's constructor to create a new instance
    let mut agent = Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.to_string(),
        document_schema_url.to_string(),
    )?;

    // Set the header and document schema URLs
    agent.set_header_schema_url(header_schema_url.to_string());
    agent.set_document_schema_url(document_schema_url.to_string());

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

/// Function to load a local document from a given path
pub fn load_local_document(path: &str) -> Result<String, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    Ok(content)
}

/// Mock function to create a test Agent with default values for agent one
pub fn load_test_agent_one(
    header_schema_url: &str,
    document_schema_url: &str,
) -> Result<Agent, Box<dyn Error>> {
    // This function should create and return a mock Agent object
    // For simplicity, we can use the `mock_test_agent` function
    mock_test_agent(header_schema_url, document_schema_url)
}

/// Mock function to create a test Agent with default values for agent two
pub fn load_test_agent_two(
    header_schema_url: &str,
    document_schema_url: &str,
) -> Result<Agent, Box<dyn Error>> {
    // This function should create and return a different mock Agent object
    // For simplicity, we can use the `mock_test_agent` function
    // In a real scenario, this function would return an Agent with different properties
    mock_test_agent(header_schema_url, document_schema_url)
}
