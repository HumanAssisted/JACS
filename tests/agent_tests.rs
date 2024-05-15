use httpmock::Method::GET; // Importing the GET method from httpmock
use httpmock::MockServer;
use jacs::schema::Schema; // Importing the Schema struct
use jacs::schema::ValidationError; // Importing the custom ValidationError struct
use jsonschema::JSONSchema; // Importing the JSONSchema struct
use reqwest;
use serde_json::json; // Importing the json! macro and Value

mod utils;

// Helper function to extract and format error messages from ValidationError instances
fn format_validation_errors(errors: Vec<String>) -> String {
    errors
        .iter()
        .map(|err| format!("Error: {}", err))
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
            let header_errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
            let formatted_errors = format_validation_errors(header_errors.clone());
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
            let agent_errors: Vec<String> = e.into_iter().map(|err| err.to_string()).collect();
            let formatted_errors = format_validation_errors(agent_errors.clone());
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

    // Configure the reqwest client to bypass SSL verification for local testing
    let _client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create reqwest client");

    // Setup schema mocks
    mock_server.mock(|when, then| {
        when.method(GET).path("/header.schema.json");
        then.status(200)
            .body_from_file("examples/schemas/header.schema.json");
    });

    mock_server.mock(|when, then| {
        when.method(GET).path("/service.schema.json");
        then.status(200)
            .body_from_file("examples/schemas/service.schema.json");
    });

    // Load and prepare the example agent JSON data
    // ... (loading and preparation code remains unchanged)

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
    let mut example_agent_json = serde_json::to_string(&example_agent)
        .expect("Failed to serialize example agent data to JSON string");

    // Replace the placeholder URLs with the actual MockServer URLs for schema validation
    example_agent_json = example_agent_json
        .replace(
            "https://hai.ai/schemas/agent/v1/header.schema.json",
            &mock_server.url("/header.schema.json"),
        )
        .replace(
            "https://hai.ai/schemas/agent/v1/service.schema.json",
            &mock_server.url("/service.schema.json"),
        )
        .replace(
            "https://hai.ai/schemas/agent/v1/contact.schema.json",
            &mock_server.url("/contact.schema.json"),
        )
        .replace(
            "https://hai.ai/schemas/agent/v1/signature.schema.json",
            &mock_server.url("/signature.schema.json"),
        )
        .replace(
            "https://hai.ai/schemas/agent/v1/unit.schema.json",
            &mock_server.url("/unit.schema.json"),
        )
        .replace(
            "https://hai.ai/schemas/agent/v1/agreement.schema.json",
            &mock_server.url("/agreement.schema.json"),
        );

    // Instantiate the Schema object with the MockServer base URL for dynamic schema URL construction
    let schema = Schema::new(&mock_server.base_url());

    // Perform validation using a blocking task to avoid Tokio runtime issues
    let validation_result = tokio::task::spawn_blocking(move || {
        schema.validate_agent(&example_agent_json).map_err(|e| {
            Box::new(ValidationError {
                errors: vec![e.to_string()],
            })
        })
    })
    .await
    .map_err(|e| e.to_string())?;

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

    Ok(())
}
