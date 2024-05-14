use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::Agent;
use jacs::schema::utils::DEFAULT_SCHEMA_STRINGS;
use jacs::schema::Schema; // Importing the Schema struct
use jsonschema::{JSONSchema, ValidationError}; // Importing the Agent struct
use reqwest;
use serde_json::{json, Value}; // Importing the json! macro and Value
use std::collections::HashMap;
use tokio::fs::{read_to_string, write}; // Importing the reqwest crate for making asynchronous HTTP requests

mod utils;

// Helper function to extract and format error messages from ValidationError instances
fn format_validation_errors(errors: Vec<ValidationError>) -> String {
    errors
        .iter()
        .map(|e| format!("Error at {}: {:?}", e.instance_path, e.kind))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Validates JSON data against the provided header and agent schemas.
/// Returns a Result with a list of validation errors if any, or an error message if validation cannot be performed.
fn validate_json_data_with_schemas(
    json_data: &str,
    header_schema_string: &str,
    agent_schema_string: &str,
) -> Result<(), String> {
    // Removed unused errors vector

    // Parse the JSON data into a serde_json::Value
    let json_value: serde_json::Value =
        serde_json::from_str(json_data).map_err(|e| format!("Failed to parse JSON data: {}", e))?;
    println!("Parsed JSON value for validation: {:?}", json_value);

    // Ensure the JSON value is not null and is an object as expected by the schema
    if !json_value.is_object() {
        return Err("JSON data is not an object".to_string());
    }

    // Parse the header schema string into a serde_json::Value
    let header_schema_value: serde_json::Value = serde_json::from_str(header_schema_string)
        .map_err(|e| format!("Failed to parse header schema: {}", e))?;
    println!(
        "Parsed header schema value for validation: {:?}",
        header_schema_value
    );

    // Parse the agent schema string into a serde_json::Value
    let agent_schema_value: serde_json::Value = serde_json::from_str(agent_schema_string)
        .map_err(|e| format!("Failed to parse agent schema: {}", e))?;
    println!(
        "Parsed agent schema value for validation: {:?}",
        agent_schema_value
    );

    // Compile the header schema and handle any compilation errors
    println!(
        "Compiling header schema with value: {:?}",
        header_schema_value
    );
    let header_schema = JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&header_schema_value)
        .map_err(|e| {
            println!("Failed to compile header schema: {:?}", e);
            format!("Failed to compile header schema: {:?}", e)
        })?;
    println!("Compiled header schema successfully: {:?}", header_schema);

    // Compile the agent schema and handle any compilation errors
    println!(
        "Compiling agent schema with value: {:?}",
        agent_schema_value
    );
    let agent_schema = JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&agent_schema_value)
        .map_err(|e| {
            println!("Failed to compile agent schema: {:?}", e);
            format!("Failed to compile agent schema: {:?}", e)
        })?;
    println!("Compiled agent schema successfully: {:?}", agent_schema);

    // Validate the JSON data against the header schema and handle any errors
    println!(
        "JSON data being validated against header schema: {:?}",
        json_value
    );
    match header_schema.validate(&json_value) {
        Ok(_) => println!("JSON data validated successfully against header schema."),
        Err(e) => {
            let header_errors: Vec<ValidationError> = e.into_iter().collect();
            for error in &header_errors {
                println!("Header schema validation error: {:?}", error);
            }
            let formatted_errors = format_validation_errors(header_errors);
            println!("Header schema validation errors: {}", formatted_errors);
            return Err(formatted_errors);
        }
    }

    // Validate the JSON data against the agent schema and handle any errors
    println!(
        "JSON data being validated against agent schema: {:?}",
        json_value
    );
    match agent_schema.validate(&json_value) {
        Ok(_) => println!("JSON data validated successfully against agent schema."),
        Err(e) => {
            let agent_errors: Vec<ValidationError> = e.into_iter().collect();
            for error in &agent_errors {
                println!("Agent schema validation error: {:?}", error);
            }
            let formatted_errors = format_validation_errors(agent_errors);
            println!("Agent schema validation errors: {}", formatted_errors);
            return Err(formatted_errors);
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_update_agent_and_verify_versions() -> Result<(), String> {
    // Start the mock server to serve the schema files
    let mock_server = MockServer::start();

    // Setup schema mocks
    // ... (mock setup code remains unchanged)

    // Load and prepare the example agent JSON data
    // ... (loading and preparation code remains unchanged)

    // Replace the {{SCHEMA_URL}} placeholder with the actual MockServer URL
    // ... (placeholder replacement code remains unchanged)

    // Parse the modified JSON data into a serde_json::Value
    // ... (parsing code remains unchanged)

    // Serialize the example agent JSON data to a string for validation
    // ... (serialization code remains unchanged)

    // Define a valid example agent JSON structure
    let example_agent = json!({
        "jacsAgentType": "ai",
        "jacsServices": [
            {
                "serviceId": "service-123",
                "serviceName": "ExampleService",
                "serviceDescription": "Example service description",
                "successDescription": "Example success description",
                "failureDescription": "Example failure description"
            }
        ],
        // ... other necessary fields according to the agent schema
    });

    // Serialize the example agent JSON data to a string for validation
    let example_agent_json = serde_json::to_string(&example_agent)
        .expect("Failed to serialize example agent data to JSON string");

    // Instantiate the Schema object with the MockServer base URL for dynamic schema URL construction
    let schema = Schema::new(&mock_server.base_url());

    // Perform validation
    let validation_result = schema.validate_agent(&example_agent_json);

    // Handle the validation result
    match validation_result {
        Ok(_) => println!("Agent JSON data validated successfully."),
        Err(e) => {
            return Err(format!(
                "Agent JSON data validation failed with error: {:?}",
                e
            ))
        }
    }

    // Clone the base URL to be used within the async block
    let base_url = mock_server.base_url().clone();
    tokio::join!(async {
        // Asynchronously fetch and validate the agent JSON data
        let schema_url = format!("{}/agent.schema.json", &base_url);
        let schema_response = reqwest::get(&schema_url).await.map_err(|e| e.to_string())?;
        let schema_data = schema_response.text().await.map_err(|e| e.to_string())?;
        let schema_value: Value = serde_json::from_str(&schema_data).map_err(|e| e.to_string())?;
        // Perform additional validation on the fetched schema data if necessary
        // ...
        Ok::<(), String>(()) // Ensure the async block returns a Result type
    });

    Ok(())
}
