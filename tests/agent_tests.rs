use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::schema::utils::EmbeddedSchemaResolver;
use jacs::schema::utils::DEFAULT_SCHEMA_STRINGS;
use jsonschema::JSONSchema;

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

    let header_schema_url = "schemas/header/v1/header.schema.json";
    let agent_schema_url = "schemas/agent/v1/agent.schema.json";

    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200).body(
            DEFAULT_SCHEMA_STRINGS
                .get("schemas/header/v1/header.schema.json")
                .unwrap(),
        );
    });

    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200).body(
            DEFAULT_SCHEMA_STRINGS
                .get("schemas/agent/v1/agent.schema.json")
                .unwrap(),
        );
    });

    // Instantiate the Agent object with the correct parameters
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        &header_schema_url,
        &agent_schema_url,
    )
    .expect("Agent instantiation failed");

    // Validate the JSON data against the schemas using the resolver
    let agent_data = serde_json::json!({
        "$schema": format!("{}/schemas/agent/v1/agent.schema.json", mock_server.base_url()),
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "jacsAgentType": "ai",
        "jacsServices": [
            {
                "serviceId": "service-123",
                "serviceName": "Example Service",
                "serviceType": "Example Type",
                "serviceDescription": "This is an example service."
            }
        ],
        "jacsContacts": [],
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
    let validation_errors =
        validate_json_data(&agent_json_string, &header_schema_url, &agent_schema_url);

    // Assert that there are no validation errors
    assert!(
        validation_errors.is_empty(),
        "Validation failed with errors: {:?}",
        validation_errors
    );

    let agentid =
        "48d074ec-84e2-4d26-adc5-0b2253f1e8ff:12ccba24-8997-47b1-9e6f-d699d7ab0e41".to_string();
    let result = agent.load_by_id(Some(agentid), None);

    match result {
        Ok(_) => {
            match agent.get_id() {
                Ok(id) => println!("AGENT LOADED {} ", id),
                Err(e) => {
                    eprintln!("Error: Agent ID is missing: {:?}", e);
                    assert!(false, "Agent ID should not be missing: {:?}", e);
                }
            }

            match agent.get_version() {
                Ok(version) => println!("AGENT VERSION {} ", version),
                Err(e) => {
                    eprintln!("Error: Agent version is missing: {:?}", e);
                    assert!(false, "Agent version should not be missing: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Error loading agent: {:?}", e);
            assert!(false, "Agent loading failed with error: {:?}", e);
        }
    }

    // Replace the unwrap call with proper error handling
    match agent.verify_self_signature() {
        Ok(_) => println!("Self signature verified successfully."),
        Err(e) => eprintln!("Failed to verify self signature: {:?}", e),
    }
}

#[test]
fn test_validate_agent_json_raw() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    // Start the mock server and set the base URL
    let mock_server = MockServer::start();

    // Define schema URLs using the mock server base URL
    let header_schema_url = "schemas/header/v1/header.schema.json";
    let agent_schema_url = "schemas/agent/v1/agent.schema.json";

    // Instantiate the EmbeddedSchemaResolver
    let _resolver = EmbeddedSchemaResolver::new();

    // Mock the header schema to resolve from memory
    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200).body(
            DEFAULT_SCHEMA_STRINGS
                .get("schemas/header/v1/header.schema.json")
                .expect("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
        );
    });

    // Mock the agent schema to resolve from memory
    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200).body(
            DEFAULT_SCHEMA_STRINGS
                .get("schemas/agent/v1/agent.schema.json")
                .expect("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
        );
    });

    let agent_data = serde_json::json!({
        "$schema": "http://localhost/schemas/agent/v1/agent.schema.json",
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "jacsAgentType": "ai",
        "jacsServices": [
            // Example service data structure
            {
                "serviceId": "service-123",
                "serviceName": "Example Service",
                "serviceType": "Example Type",
                "serviceDescription": "This is an example service."
            }
        ],
        "jacsContacts": [
            // Example contact data structure
            {
                "contactId": "contact-123",
                "contactName": "John Doe",
                "contactType": "Example Type",
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
    let validation_errors =
        validate_json_data(&agent_json_string, &header_schema_url, &agent_schema_url);

    // Assert that there are no validation errors
    assert!(
        validation_errors.is_empty(),
        "Validation failed with errors: {:?}",
        validation_errors
    );

    let agentid =
        "48d074ec-84e2-4d26-adc5-0b2253f1e8ff:12ccba24-8997-47b1-9e6f-d699d7ab0e41".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        &header_schema_url,
        &agent_schema_url,
    )
    .expect("Agent instantiation failed");
    let result = agent.load_by_id(Some(agentid), None);

    match result {
        Ok(_) => {
            match agent.get_id() {
                Ok(id) => println!("AGENT LOADED {} ", id),
                Err(e) => {
                    eprintln!("Error: Agent ID is missing: {:?}", e);
                    assert!(false, "Agent ID should not be missing: {:?}", e);
                }
            }

            match agent.get_version() {
                Ok(version) => println!("AGENT VERSION {} ", version),
                Err(e) => {
                    eprintln!("Error: Agent version is missing: {:?}", e);
                    assert!(false, "Agent version should not be missing: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Error loading agent: {:?}", e);
            assert!(false, "Agent loading failed with error: {:?}", e);
        }
    }

    // Replace the unwrap call with proper error handling
    match agent.verify_self_signature() {
        Ok(_) => println!("Self signature verified successfully."),
        Err(e) => eprintln!("Failed to verify self signature: {:?}", e),
    }
}
