use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::schema::utils::DEFAULT_SCHEMA_STRINGS;
use jsonschema::{JSONSchema, ValidationError};

mod utils;

/// Validates JSON data against the provided schemas.
/// Returns a list of validation errors, if any.
fn validate_json_data(
    json_data: &str,
    header_schema_url: &str,
    agent_schema_url: &str,
) -> Vec<String> {
    let mut errors = Vec::new();

    // Parse the JSON data into a serde_json::Value
    let json_value: serde_json::Value = match serde_json::from_str(json_data) {
        Ok(value) => {
            // Log the parsed JSON value for debugging purposes
            println!("Parsed JSON data: {:?}", value);
            value
        }
        Err(e) => {
            errors.push(format!("Failed to parse JSON data: {}", e));
            return errors;
        }
    };

    // Compile the header schema
    let header_schema_value = serde_json::from_str::<serde_json::Value>(
        DEFAULT_SCHEMA_STRINGS
            .get(header_schema_url)
            .expect("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
    )
    .expect("Failed to parse header schema into Value");

    let header_schema =
        JSONSchema::compile(&header_schema_value).expect("Failed to compile header schema");

    // Compile the agent schema
    let agent_schema_value = serde_json::from_str::<serde_json::Value>(
        DEFAULT_SCHEMA_STRINGS
            .get(agent_schema_url)
            .expect("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
    )
    .expect("Failed to parse agent schema into Value");

    let agent_schema =
        JSONSchema::compile(&agent_schema_value).expect("Failed to compile agent schema");

    // Validate the JSON data against the header schema
    let header_schema_result = header_schema.validate(&json_value);
    if let Err(validation_errors) = header_schema_result {
        for error in validation_errors {
            errors.push(format!("Header schema validation error: {}", error));
        }
    } else {
        println!("Header schema validated successfully.");
    }

    // Validate the JSON data against the agent schema
    let agent_schema_result = agent_schema.validate(&json_value);
    if let Err(validation_errors) = agent_schema_result {
        for error in validation_errors {
            errors.push(format!("Agent schema validation error: {}", error));
        }
    } else {
        println!("Agent schema validated successfully.");
    }

    errors
}

#[test]
fn test_update_agent_and_verify_versions() {
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    let mock_server = MockServer::start();

    let header_schema_url = format!(
        "{}/schemas/header/v1/header.schema.json",
        mock_server.base_url()
    );
    let agent_schema_url = format!(
        "{}/schemas/agent/v1/agent.schema.json",
        mock_server.base_url()
    );

    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200).body(
            DEFAULT_SCHEMA_STRINGS
                .get("schemas/header/v1/header.schema.json")
                .expect("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
        );
    });

    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200).body(
            DEFAULT_SCHEMA_STRINGS
                .get("schemas/agent/v1/agent.schema.json")
                .expect("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
        );
    });

    // Print the header schema string in smaller parts to avoid truncation
    let header_schema_string = DEFAULT_SCHEMA_STRINGS
        .get("schemas/header/v1/header.schema.json")
        .expect("Header schema string not found in DEFAULT_SCHEMA_STRINGS");
    for i in (0..header_schema_string.len()).step_by(500) {
        let end = std::cmp::min(i + 500, header_schema_string.len());
        println!("Header schema part: {}", &header_schema_string[i..end]);
    }

    // Print the agent schema string in smaller parts to avoid truncation
    let agent_schema_string = DEFAULT_SCHEMA_STRINGS
        .get("schemas/agent/v1/agent.schema.json")
        .expect("Agent schema string not found in DEFAULT_SCHEMA_STRINGS");
    for i in (0..agent_schema_string.len()).step_by(500) {
        let end = std::cmp::min(i + 500, agent_schema_string.len());
        println!("Agent schema part: {}", &agent_schema_string[i..end]);
    }

    // Instantiate the Agent object with the correct parameters
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();

    // Serialize the agent_data to a JSON string and ensure it is not 'null'
    let agent_data = serde_json::json!({
        "$schema": agent_schema_url,
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "jacsAgentType": "ai",
        "jacsServices": [
            {
                "serviceId": "service-123",
                "serviceName": "Example Service",
                "serviceDescription": "This is an example service."
            }
        ],
        "jacsContacts": [
            {
                "contactId": "contact-123",
                "contactType": "Example Contact Type",
                "contactDetails": "This is an example contact."
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
        "jacsOriginalDate": "2024-04-20T05:46:34.271322+00:00"
    });
    let agent_json_string = serde_json::to_string(&agent_data)
        .expect("Failed to serialize agent object to JSON string");

    // Ensure the JSON string is not 'null' or empty
    assert!(!agent_json_string.is_empty(), "The JSON string is empty.");
    assert_ne!(agent_json_string, "null", "The JSON string is 'null'.");

    // Log the JSON string to be loaded
    println!("JSON string to be loaded: {}", agent_json_string);

    // Log the schemas being used for validation
    println!("Header schema URL: {}", header_schema_url);
    println!("Agent schema URL: {}", agent_schema_url);

    // Attempt to create and load the agent with the non-'null' JSON string
    let agent_result = jacs::agent::Agent::create_agent_and_load(
        &agent_version,
        &header_version,
        header_schema_url,
        agent_schema_url,
        &agent_json_string,
    );

    // Log the result of the create_agent_and_load function
    match &agent_result {
        Ok(agent) => println!("Agent created and loaded successfully: {:?}", agent),
        Err(e) => {
            eprintln!("Failed to create and load agent. Error: {:?}", e);
            if let Some(validation_error) = e.downcast_ref::<ValidationError>() {
                eprintln!("Detailed validation error: {:?}", validation_error);
            }
        }
    }

    // Assert that the agent creation and loading did not result in an error
    assert!(
        agent_result.is_ok(),
        "Test failed due to validation errors."
    );

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
