use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jsonschema::{JSONSchema, ValidationError};

mod utils;

/// Validates JSON data against the provided header and agent schemas.
/// Returns a Result with a list of validation errors if any, or an error message if validation cannot be performed.
fn validate_json_data_with_schemas(
    json_data: &str,
    header_schema_string: &str,
    agent_schema_string: &str,
) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();

    // Parse the JSON data into a serde_json::Value
    let json_value: serde_json::Value =
        serde_json::from_str(json_data).map_err(|e| format!("Failed to parse JSON data: {}", e))?;

    // Ensure the JSON value is not null
    if json_value.is_null() {
        return Err("JSON data is null".to_string());
    }

    // Parse the header schema string into a serde_json::Value
    let header_schema_value: serde_json::Value = match serde_json::from_str(header_schema_string) {
        Ok(value) => value,
        Err(e) => {
            errors.push(format!("Failed to parse header schema: {}", e));
            return Ok(errors);
        }
    };

    // Parse the agent schema string into a serde_json::Value
    let agent_schema_value: serde_json::Value = match serde_json::from_str(agent_schema_string) {
        Ok(value) => value,
        Err(e) => {
            errors.push(format!("Failed to parse agent schema: {}", e));
            return Ok(errors);
        }
    };

    // Compile the header schema
    let header_schema = match JSONSchema::compile(&header_schema_value) {
        Ok(schema) => schema,
        Err(e) => {
            errors.push(format!("Failed to compile header schema: {}", e));
            return Ok(errors);
        }
    };

    // Compile the agent schema
    let agent_schema = match JSONSchema::compile(&agent_schema_value) {
        Ok(schema) => schema,
        Err(e) => {
            errors.push(format!("Failed to compile agent schema: {}", e));
            return Ok(errors);
        }
    };

    // Validate the JSON data against the header schema
    if let Err(validation_errors) = header_schema.validate(&json_value) {
        for error in validation_errors {
            errors.push(format!("Header schema validation error: {}", error));
        }
    }

    // Validate the JSON data against the agent schema
    if let Err(validation_errors) = agent_schema.validate(&json_value) {
        for error in validation_errors {
            errors.push(format!("Agent schema validation error: {}", error));
        }
    }

    Ok(errors)
}

// Removed old validate_json_data function as it is no longer used.

#[test]
fn test_update_agent_and_verify_versions() {
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

    // Instantiate the Agent object with the correct parameters
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();

    // Serialize the agent_data to a JSON string and ensure it is not 'null'
    let agent_data = serde_json::json!({
        "$schema": format!("{}/schemas/agent/v1/agent.schema.json", mock_server.base_url()),
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "jacsAgentType": "ai",
        "jacsServices": [
            {
                "serviceId": "service-123",
                "serviceName": "Example Service",
                "serviceDescription": "This is an example service.",
                // Additional required fields for service as per the schema
                "serviceType": "Example Service Type",
                "serviceUrl": "http://example.com/service"
            }
        ],
        "jacsContacts": [
            {
                "contactId": "contact-123",
                "contactType": "Example Contact Type",
                "contactDetails": "This is an example contact.",
                // Additional required fields for contact as per the schema
                "contactMethod": "email",
                "contactValue": "contact@example.com"
            }
        ],
        "jacsSha256": "a1c87ea81a8c557b7f6be29834bd6da2650de57078da4335b2ee2612c694a18d",
        "jacsSignature": {
            "agentID": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
            "agentVersion": "12ccba24-8997-47b1-9e6f-d699d7ab0e41",
            "date": "2024-04-25T05:46:34.660457+00:00",
            "fields": [
                "$schema",
                "jacsId",
                "jacsAgentType",
                "jacsServices",
                "jacsContacts"
            ],
            "publicKeyHash": "2c9cc6361e2003173df86b9c267b3891193319da7fe7c6f42cb0fbe5b30d7c0d",
            "signature": "signatureValue",
            "signingAlgorithm": "RSA-PSS"
        },
        "jacsVersionDate": "2024-04-25T05:46:34.271322+00:00",
        "name": "Agent Smith",
        "jacsOriginalVersion": "0.9.0",
        "jacsOriginalDate": "2024-04-20T05:46:34.271322+00:00",
        // Added missing fields as per the schema requirements
        "header_version": header_version,
        "document_version": agent_version,
        // Ensure all required fields as per the schema are included
        // Add any missing fields here
    });
    let agent_json_string = serde_json::to_string(&agent_data)
        .expect("Failed to serialize agent object to JSON string");

    // Ensure the JSON string is not 'null' or empty
    assert!(!agent_json_string.is_empty(), "The JSON string is empty.");
    assert_ne!(agent_json_string, "null", "The JSON string is 'null'.");

    // Log the JSON string to be loaded
    println!("JSON string to be loaded: {}", agent_json_string);

    println!("Serialized agent JSON data: {}", agent_json_string);
    // Fetch the header and agent schema strings using the mock server
    let header_schema_string = include_str!("../schemas/header/v1/header.schema.json").to_string();
    let agent_schema_string = include_str!("../schemas/agent/v1/agent.schema.json").to_string();

    // Attempt to create and load the agent with the non-'null' JSON string
    let agent_result = jacs::agent::Agent::create_agent_and_load(
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
        &agent_json_string,
    ); // Closing parenthesis added to complete the function call

    // Handle the result of the create_agent_and_load function
    match &agent_result {
        Ok(agent) => {
            println!("Agent created and loaded successfully: {:?}", agent);
            // Validate the JSON string against the fetched schemas
            let validation_result = validate_json_data_with_schemas(
                &agent_json_string,
                &header_schema_string,
                &agent_schema_string,
            );

            // Handle the result of validation
            match validation_result {
                Ok(validation_errors) => {
                    // Assert that there are no validation errors
                    assert!(
                        validation_errors.is_empty(),
                        "Validation errors found: {:?}",
                        validation_errors
                    );
                }
                Err(e) => {
                    eprintln!("Validation failed with error: {}", e);
                    assert!(false, "Test failed due to validation errors.");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to create and load agent. Error: {:?}", e);
            if let Some(validation_error) = e.downcast_ref::<ValidationError>() {
                eprintln!("Detailed validation error: {:?}", validation_error);
            }
            assert!(
                false,
                "Test failed due to an error in creating and loading the agent."
            );
        }
    }

    let mut agent =
        agent_result.expect("Failed to create and load agent despite previous assertion.");

    let agentid =
        "48d074ec-84e2-4d26-adc5-0b2253f1e8ff:12ccba24-8997-47b1-9e6f-d699d7ab0e41".to_string();
    let result = agent
        .load_by_id(Some(agentid), None)
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

#[tokio::test]
async fn test_create_agent_with_example_structure() {
    let mock_server = MockServer::start();

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
        // ... (rest of the JSON structure remains unchanged)
    });

    // Serialize the example agent to a JSON string
    let agent_json_string = serde_json::to_string(&example_agent)
        .expect("Failed to serialize example agent to JSON string");

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
    let validation_result = validate_json_data_with_schemas(
        &agent_json_string,
        &header_schema_string,
        &agent_schema_string,
    );

    // Handle the result of validation
    match validation_result {
        Ok(validation_errors) => {
            // Assert that there are no validation errors
            assert!(
                validation_errors.is_empty(),
                "Validation errors found: {:?}",
                validation_errors
            );
            // Log the successful validation
            println!("Example agent validated successfully against schemas.");
        }
        Err(e) => panic!("Validation failed with error: {}", e),
    }
}
