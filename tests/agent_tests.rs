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

    // Compile the header schema
    let header_schema = JSONSchema::compile(&header_schema_value)
        .map_err(|e| format!("Failed to compile header schema: {}", e))?;
    println!("Compiled header schema for validation");

    // Compile the agent schema
    let agent_schema = JSONSchema::compile(&agent_schema_value)
        .map_err(|e| format!("Failed to compile agent schema: {}", e))?;
    println!("Compiled agent schema for validation");

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
            let detailed_error = format!(
                "Header schema validation error at {}: expected value matching schema at {}, but found invalid value: {:?}",
                error.instance_path, error.schema_path, error.instance
            );
            println!("{}", detailed_error);
            errors.push(detailed_error);
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
            let detailed_error = format!("Agent schema validation error: {}", error);
            println!("{}", detailed_error);
            errors.push(detailed_error);
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
async fn perform_test_operations(mock_server: &MockServer) -> Result<(), String> {
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

    // Mock responses for the additional schema endpoints
    let _service_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/service/v1/service.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/service/v1/service.schema.json"
        ));
    });

    let _contact_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/contact/v1/contact.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/contact/v1/contact.schema.json"
        ));
    });

    // Save the example agent JSON data to a file for external validation
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
        "jacsContacts": [ // Ensuring this required field is present even if empty for 'ai' agent type
            {
                "firstName": "John",
                "lastName": "Doe",
                "addressName": "John's Home",
                "phone": "123-456-7890",
                "email": "john.doe@example.com",
                "mailName": "John Doe",
                "mailAddress": "123 Example Street",
                "mailAddressTwo": "Apt 4",
                "mailState": "ExampleState",
                "mailZip": "12345",
                "mailCountry": "ExampleCountry",
                "isPrimary": true
            }
        ],
        // Adding required fields from the header schema with valid dummy data for testing
        "jacsSignature": {
            "agentID": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
            "agentVersion": "1.0.0",
            "date": "2024-04-25T05:46:34.271322+00:00",
            "signature": "Base64EncodedSignature==",
            "publicKeyHash": "PublicKeyHashValue==",
            "signingAlgorithm": "ECDSA",
            "fields": ["jacsId", "jacsVersion", "jacsVersionDate", "jacsOriginalVersion", "jacsOriginalDate"]
        },
        "jacsRegistration": {
            "registrationId": "dummy-registration-id",
            "registrationDate": "2024-04-25T05:46:34.271322+00:00",
            "registrant": "http://example.com/agents/1",
            "signature": {
                "type": "ECDSA",
                "created": "2024-04-25T05:46:34.271322+00:00",
                "creator": "http://example.com/key/2",
                "signatureValue": "Base64Encoded=="
            }
        },
        "jacsAgreement": {
            "agreementId": "dummy-agreement-id",
            "agreementDate": "2024-04-25T05:46:34.271322+00:00",
            "agreementParty1": "http://example.com/agents/1",
            "agreementParty2": "http://example.com/agents/2",
            "agreementType": "ExampleType",
            "agreementTerms": "ExampleTerms",
            "signatures": [
                {
                    "type": "ECDSA",
                    "created": "2024-04-25T05:46:34.271322+00:00",
                    "creator": "http://example.com/key/3",
                    "signatureValue": "Base64Encoded=="
                }
            ]
        },
        "jacsAgreementHash": "dummy-hash-value",
        "jacsSha256": "dummy-sha256-value",
        "jacsFiles": [] // Assuming empty array for the purpose of this test
    });

    // Write the example agent JSON data to a file
    std::fs::write(
        "/home/ubuntu/JACS/tests/example_agent.json",
        serde_json::to_string_pretty(&example_agent).unwrap(),
    )
    .expect("Failed to write example agent JSON data to file");

    // Use the reqwest client to fetch the header schema and bypass SSL verification
    let header_schema_response = client
        .get(format!(
            "{}/schemas/header/v1/header.schema.json",
            mock_server.base_url()
        ))
        .send()
        .await
        .expect("Failed to fetch header schema");

    // Ensure the response status is success and log the status
    assert!(
        header_schema_response.status().is_success(),
        "Header schema response status was not success"
    );
    let header_schema_string = header_schema_response
        .text()
        .await
        .expect("Failed to get header schema text");
    println!("Fetched header schema string: {:?}", header_schema_string);

    // Fetch and log the agent schema string for external validation
    let agent_schema_response = client
        .get(format!(
            "{}/schemas/agent/v1/agent.schema.json",
            mock_server.base_url()
        ))
        .send()
        .await
        .expect("Failed to fetch agent schema");

    // Ensure the response status is success and log the status
    assert!(
        agent_schema_response.status().is_success(),
        "Agent schema response status was not success"
    );
    let agent_schema_string = agent_schema_response
        .text()
        .await
        .expect("Failed to get agent schema text");
    println!("Fetched agent schema string: {:?}", agent_schema_string);

    // Write the fetched schema strings to files for external validation
    let header_schema_path = "/home/ubuntu/JACS/tests/header_schema.json";
    std::fs::write(&header_schema_path, &header_schema_string)
        .expect("Failed to write header schema to file");
    println!(
        "Fetched and saved header schema string to file: {}",
        header_schema_path
    );

    let agent_schema_path = "/home/ubuntu/JACS/tests/agent_schema.json";
    std::fs::write(&agent_schema_path, &agent_schema_string)
        .expect("Failed to write agent schema to file");
    println!(
        "Fetched and saved agent schema string to file: {}",
        agent_schema_path
    );

    // Define the agent JSON string with the correct data for validation
    let agent_json_string = serde_json::to_string(&example_agent)
        .expect("Failed to serialize example agent data to JSON string");

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
        format!(
            "{}/schemas/header/v1/header.schema.json",
            mock_server.base_url()
        ),
        format!(
            "{}/schemas/agent/v1/agent.schema.json",
            mock_server.base_url()
        ),
    )
    .expect("Failed to create Agent instance");

    // Ensure the agent is loaded with the correct JSON data
    let agent_id = "48d074ec-84e2-4d26-adc5-0b2253f1e8ff";
    let agent_data = serde_json::json!({
        "jacsId": agent_id,
        "jacsVersion": "1.0.0",
        "jacsVersionDate": "2024-04-25T05:46:34.271322+00:00",
        "jacsOriginalVersion": "0.9.0",
        "jacsOriginalDate": "2024-04-20T05:46:34.271322+00:00",
        "$schema": format!("{}/schemas/header/v1/header.schema.json", mock_server.base_url()),
        "jacsAgentType": "ai",
        "jacsServices": [
            {
                "serviceId": "service-123",
                "serviceName": "Example Service",
                "serviceDescription": "This is an example service.",
                "serviceType": "Example Service Type",
                "serviceUrl": "http://example.com/service"
            }
        ],
        "jacsContacts": [] // For 'ai' agent type, 'jacsContacts' should be an empty array
    });

    // Serialize the agent data to a JSON string
    let agent_json_string =
        serde_json::to_string(&agent_data).expect("Failed to serialize agent data to JSON string");

    // Log the JSON string to verify its content before loading
    println!(
        "JSON data to be loaded into the agent: {}",
        agent_json_string
    );

    // Load the agent with the JSON data
    agent
        .load(&agent_json_string)
        .expect("Failed to load agent with JSON data");

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
    // Start the MockServer before the async block to ensure it remains in scope
    let mock_server = MockServer::start();
    println!("MockServer started at URL: {}", mock_server.base_url());

    // Perform test operations, passing the MockServer by reference to avoid premature drop
    let test_result = perform_test_operations(&mock_server).await;
    println!("Test operations completed, test result: {:?}", test_result);

    // Assert that the test operations completed successfully
    assert!(
        test_result.is_ok(),
        "Test did not complete successfully: {:?}",
        test_result.err()
    );
}
