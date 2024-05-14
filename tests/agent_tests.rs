use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::Agent;
use jsonschema::{JSONSchema, ValidationError}; // Importing the Agent struct

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
    let mock_server = MockServer::start();
    let header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200)
            .body(include_str!("../schemas/header/v1/header.schema.json"));
    });
    let agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200)
            .body(include_str!("../schemas/agent/v1/agent.schema.json"));
    });
    // Mock additional schema files referenced by the agent schema
    let service_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/service/v1/service.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/service/v1/service.schema.json"
        ));
    });
    let contact_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/contact/v1/contact.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/contact/v1/contact.schema.json"
        ));
    });
    let signature_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/signature/v1/signature.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/signature/v1/signature.schema.json"
        ));
    });
    let agreement_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/agreement/v1/agreement.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/agreement/v1/agreement.schema.json"
        ));
    });
    let files_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/files/v1/files.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/files/v1/files.schema.json"
        ));
    });
    // Add more mocks for other referenced schema files as needed
    // ...

    // Define the agent and header versions
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();

    println!(
        "Header schema URL: {}",
        format!(
            "{}/schemas/header/v1/header.schema.json",
            mock_server.base_url()
        )
    );
    println!(
        "Agent schema URL: {}",
        format!(
            "{}/schemas/agent/v1/agent.schema.json",
            mock_server.base_url()
        )
    );

    println!(
        "Attempting to create Agent instance with header schema URL: {}",
        format!(
            "{}/schemas/header/v1/header.schema.json",
            mock_server.base_url()
        )
    );
    println!(
        "Attempting to create Agent instance with agent schema URL: {}",
        format!(
            "{}/schemas/agent/v1/agent.schema.json",
            mock_server.base_url()
        )
    );

    // Load the example agent JSON data from the file
    let example_agent_json = std::fs::read_to_string("/home/ubuntu/JACS/tests/example_agent.json")
        .map_err(|e| format!("Failed to read example agent JSON data from file: {}", e))?;
    println!("Raw example agent JSON data: {}", example_agent_json);

    // Replace the {{SCHEMA_URL}} placeholder with the actual MockServer URL
    let example_agent_json = example_agent_json.replace("{{SCHEMA_URL}}", &mock_server.base_url());
    println!(
        "Example agent JSON data after placeholder replacement: {}",
        example_agent_json
    );

    // Parse the modified JSON data into a serde_json::Value
    let example_agent: serde_json::Value = serde_json::from_str(&example_agent_json)
        .map_err(|e| format!("Failed to parse example agent JSON data: {}", e))?;
    println!(
        "Parsed example agent JSON data for validation: {:?}",
        example_agent
    );

    // Instantiate the Agent object with the correct parameters
    let _agent = Agent::new(
        &agent_version,
        &header_version,
        format!(
            "{}/schemas/header/v1/header.schema.json",
            mock_server.base_url()
        ),
        format!(
            "{}/schemas/agent/v1/agent.schema.json",
            mock_server.base_url()
        ),
    )
    .map_err(|e| format!("Failed to create Agent instance: {}", e))?;

    println!(
        "Example agent JSON data being validated: {}",
        serde_json::to_string_pretty(&example_agent)
            .expect("Failed to serialize example agent data to JSON string")
    );

    // Write the example agent JSON data to a file for external validation
    std::fs::write(
        "/home/ubuntu/JACS/tests/example_agent.json",
        serde_json::to_string_pretty(&example_agent)
            .map_err(|e| format!("Failed to serialize example agent JSON data: {}", e))?,
    )
    .map_err(|e| format!("Failed to write example agent JSON data to file: {}", e))?;
    println!("MockServer: Example agent JSON data written to file for external validation");

    // Serialize the example agent JSON data to a string for validation
    let example_agent_json = serde_json::to_string(&example_agent)
        .expect("Failed to serialize example agent data to JSON string");
    println!(
        "Serialized example agent JSON data for validation: {}",
        example_agent_json
    );

    // Read the header and agent schema content from files
    let header_schema_content = include_str!("../schemas/header/v1/header.schema.json");
    let agent_schema_content = include_str!("../schemas/agent/v1/agent.schema.json");
    println!(
        "Header schema content for validation: {}",
        header_schema_content
    );
    println!(
        "Agent schema content for validation: {}",
        agent_schema_content
    );

    // Validate the JSON string against the fetched schemas
    println!(
        "Validating JSON data against schemas. Data to validate: {:?}",
        example_agent
    );
    validate_json_data_with_schemas(
        &example_agent_json,
        header_schema_content,
        agent_schema_content,
    )
    .map_err(|e| {
        println!("Validation failed with error: {}", e);
        e
    })?;
    println!("JSON data validated successfully against header and agent schemas.");

    // Explicitly keep the MockServer and its mocks in scope until all async operations are complete
    // by storing them in variables that are not dropped until the end of the function.
    // This ensures that the Tokio runtime is not dropped prematurely.
    let _ = header_schema_mock;
    let _ = agent_schema_mock;
    let _ = service_schema_mock;
    let _ = contact_schema_mock;
    let _ = signature_schema_mock;
    let _ = agreement_schema_mock;
    let _ = files_schema_mock;
    let _ = mock_server;

    Ok(())
}
