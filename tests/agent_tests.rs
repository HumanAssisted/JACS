use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::Agent;
use jsonschema::JSONSchema;

mod utils;

/// Validates JSON data against the provided header and agent schemas.
/// Returns a Result with a list of validation errors if any, or an error message if validation cannot be performed.
fn validate_json_data_with_schemas(
    json_data: &str,
    header_schema_string: &str,
    agent_schema_string: &str,
) -> Result<(), String> {
    let mut errors = Vec::new();

    // Parse the JSON data into a serde_json::Value
    let json_value: serde_json::Value =
        serde_json::from_str(json_data).map_err(|e| format!("Failed to parse JSON data: {}", e))?;
    println!("Parsed JSON value for validation: {:?}", json_value);

    // Ensure the JSON value is not null
    if json_value.is_null() {
        return Err("JSON data is null".to_string());
    }

    // Parse the header schema string into a serde_json::Value
    let header_schema_value: serde_json::Value = match serde_json::from_str(header_schema_string) {
        Ok(value) => value,
        Err(e) => {
            return Err(format!("Failed to parse header schema: {}", e));
        }
    };

    // Parse the agent schema string into a serde_json::Value
    let agent_schema_value: serde_json::Value = match serde_json::from_str(agent_schema_string) {
        Ok(value) => value,
        Err(e) => {
            errors.push(format!("Failed to parse agent schema: {}", e));
            return Err(format!("Failed to parse agent schema: {}", e));
        }
    };

    // Compile the header schema
    let header_schema = match JSONSchema::compile(&header_schema_value) {
        Ok(schema) => schema,
        Err(e) => {
            return Err(format!("Failed to compile header schema: {}", e));
        }
    };

    // Compile the agent schema
    let agent_schema = match JSONSchema::compile(&agent_schema_value) {
        Ok(schema) => schema,
        Err(e) => {
            errors.push(format!("Failed to compile agent schema: {}", e));
            return Err(errors.join(", "));
        }
    };

    // Log the JSON data and header schema just before validation
    println!(
        "Validating JSON data against the header schema: {:?}",
        json_value
    );
    println!(
        "Header schema being used for validation: {:?}",
        header_schema_value
    );

    // Validate the JSON data against the header schema
    if let Err(validation_errors) = header_schema.validate(&json_value) {
        for error in validation_errors {
            println!("Header schema validation error: {:?}", error);
            errors.push(format!("Header schema validation error: {}", error));
        }
    }

    // Log the JSON data and agent schema just before validation
    println!(
        "Validating JSON data against the agent schema: {:?}",
        json_value
    );
    println!(
        "Agent schema being used for validation: {:?}",
        agent_schema_value
    );

    // Validate the JSON data against the agent schema
    if let Err(validation_errors) = agent_schema.validate(&json_value) {
        for error in validation_errors {
            println!("Agent schema validation error: {:?}", error);
            errors.push(format!("Agent schema validation error: {}", error));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(", ")) // Combine all error messages into a single string
    }
}

/// Performs test operations for creating an agent with an example structure.
/// This function takes a MockServer and performs all the operations
/// required for the test, including fetching schemas and validating JSON data.
async fn perform_test_operations(mock_server: MockServer) -> Result<(), String> {
    // Configure the client to bypass SSL verification for local testing
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create HTTP client");

    // Mock responses for the schema endpoints
    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200)
            .body(include_str!("../schemas/header/v1/header.schema.json"));
    });

    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200)
            .body(include_str!("../schemas/agent/v1/agent.schema.json"));
    });

    // Define the example agent structure based on the example JSON file
    let example_agent = serde_json::json!({
        "$schema": format!("{}/schemas/header/v1/header.schema.json", mock_server.base_url()),
        "jacsId": "example-id",
        "jacsVersion": "1.0.0",
        "jacsVersionDate": "2024-04-25T05:46:34.271322+00:00",
        "jacsOriginalVersion": "0.9.0",
        "jacsOriginalDate": "2024-04-20T05:46:34.271322+00:00",
        "jacsAgentType": "ai", // Ensuring this required field is present
        "jacsServices": [ // Ensuring this required field is present with at least one service
            {
                "serviceId": "service-123",
                "serviceName": "Example Service",
                "serviceDescription": "This is an example service.",
                "serviceType": "Example Service Type",
                "serviceUrl": "http://example.com/service"
            }
        ],
        // "jacsContacts" is not required for "ai" agent type, but if changed to "human", "human-org", or "hybrid", it must be included with at least one contact
    });

    // Serialize the example agent to a JSON string
    let agent_json_string = serde_json::to_string(&example_agent)
        .expect("Failed to serialize example agent to JSON string");

    println!("Serialized JSON data: {}", agent_json_string);

    // Use the reqwest client to fetch the schemas and bypass SSL verification
    let header_schema_string = client
        .get(format!(
            "{}/schemas/header/v1/header.schema.json",
            mock_server.base_url()
        ))
        .send()
        .await
        .expect("Failed to fetch header schema")
        .text()
        .await
        .expect("Failed to get header schema text");

    let agent_schema_string = client
        .get(format!(
            "{}/schemas/agent/v1/agent.schema.json",
            mock_server.base_url()
        ))
        .send()
        .await
        .expect("Failed to fetch agent schema")
        .text()
        .await
        .expect("Failed to get agent schema text");

    // Validate the JSON string against the fetched schemas
    validate_json_data_with_schemas(
        &agent_json_string,
        &header_schema_string,
        &agent_schema_string,
    )
    .map_err(|e| format!("Validation failed: {}", e))
}

#[tokio::test]
async fn test_update_agent_and_verify_versions() {
    let mock_server = MockServer::start();

    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200)
            .body(include_str!("../schemas/header/v1/header.schema.json"));
    });

    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200)
            .body(include_str!("../schemas/agent/v1/agent.schema.json"));
    });

    // Define the agent and header versions
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();

    // Instantiate the Agent object with the correct parameters
    let mut agent = Agent::new(
        &agent_version,
        &header_version,
        mock_server.base_url().to_string() + "/schemas/header/v1/header.schema.json",
        mock_server.base_url().to_string() + "/schemas/agent/v1/agent.schema.json",
    )
    .expect("Failed to create Agent instance");

    // Load the agent by ID
    let agent_id = "48d074ec-84e2-4d26-adc5-0b2253f1e8ff".to_string();
    agent
        .load_by_id(Some(agent_id), None)
        .expect("Failed to load agent by ID");

    println!(
        "AGENT LOADED {}",
        agent.get_id().expect("Failed to get agent ID")
    );
    println!(
        "AGENT VERSION {}",
        agent.get_version().expect("Failed to get agent version")
    );

    agent
        .verify_self_signature()
        .expect("Failed to verify self signature");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_agent_with_example_structure() {
    let mock_server = MockServer::start();
    println!("MockServer started, about to perform test operations");
    let test_result = perform_test_operations(mock_server.clone()).await;
    println!("Test operations completed, test result: {:?}", test_result);

    // Assert that the test result is successful
    assert!(
        test_result.is_ok(),
        "Test did not complete successfully: {:?}",
        test_result.err()
    );
}
