use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::schema::utils::EmbeddedSchemaResolver;
use jacs::schema::utils::DEFAULT_SCHEMA_STRINGS;
use jsonschema::JSONSchema;
use jsonschema::SchemaResolver;

use url::Url;

mod utils;

#[test]
fn test_update_agent_and_verify_versions() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    // Start the mock server and set the base URL
    let mock_server = MockServer::start();
    let base_url = mock_server.url("");

    // Define schema URLs using the mock server base URL
    let header_schema_url = format!("{}/schemas/header/v1/header.schema.json", base_url);
    let agent_schema_url = format!("{}/schemas/agent/v1/agent.schema.json", base_url);
    let agreement_schema_url = format!(
        "{}/schemas/components/agreement/v1/agreement.schema.json",
        base_url
    );
    let files_schema_url = format!("{}/schemas/components/files/v1/files.schema.json", base_url);
    let signature_schema_url = format!(
        "{}/schemas/components/signature/v1/signature.schema.json",
        base_url
    );

    // Instantiate the EmbeddedSchemaResolver with the mock server base URL
    let _resolver = EmbeddedSchemaResolver::new();

    // Mock the header schema
    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS.get("schemas/header/v1/header.schema.json") {
                Some(schema_str) => schema_str,
                None => panic!("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    // Mock the agent schema
    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS.get("schemas/agent/v1/agent.schema.json") {
                Some(schema_str) => schema_str,
                None => panic!("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    // Mock the agreement schema
    let _agreement_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/agreement/v1/agreement.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS
                .get("schemas/components/agreement/v1/agreement.schema.json")
            {
                Some(schema_str) => schema_str,
                None => panic!("Agreement schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    // Mock the files schema
    let _files_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/files/v1/files.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS.get("schemas/components/files/v1/files.schema.json") {
                Some(schema_str) => schema_str,
                None => panic!("Files schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    // Mock the signature schema
    let _signature_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/signature/v1/signature.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS
                .get("schemas/components/signature/v1/signature.schema.json")
            {
                Some(schema_str) => schema_str,
                None => panic!("Signature schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.to_string(),
        agent_schema_url.to_string(),
    )
    .expect("Agent schema should have instantiated");
    let agentid =
        "48d074ec-84e2-4d26-adc5-0b2253f1e8ff:12ccba24-8997-47b1-9e6f-d699d7ab0e41".to_string();
    let result = agent.load_by_id(Some(agentid), None);

    match result {
        Ok(_) => {
            println!(
                "AGENT LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {:?}", e);
            assert!(false, "Agent loading failed with error: {:?}", e);
        }
    }

    let modified_agent_string = r#"{
    "$schema": "http://localhost/schemas/agent/v1/agent.schema.json",
    "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
    "jacsVersion": "1.0.0",
    "jacsAgentType": "ai",
    "jacsServices": [
        {
            "serviceId": "service123",
            "serviceName": "Test Service",
            "serviceDescription": "A test service for validation purposes",
            "tools": [
                {
                    "function": {
                        "name": "ExampleFunction",
                        "parameters": {
                            "param1": "A string parameter",
                            "param2": 42
                        }
                    },
                    "type": "function",
                    "url": "https://api.example.com/tool"
                }
            ]
        }
    ],
    "jacsContacts": [
        {
            "contactId": "contact123",
            "contactType": "email",
            "contactDetails": "agent.smith@example.com"
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
}"#
    .replace(
        "http://localhost/schemas/agent/v1/agent.schema.json",
        &agent_schema_url,
    )
    .replace(
        "http://localhost/schemas/components/agreement/v1/agreement.schema.json",
        &agreement_schema_url,
    )
    .replace(
        "http://localhost/schemas/components/files/v1/files.schema.json",
        &files_schema_url,
    )
    .replace(
        "http://localhost/schemas/components/signature/v1/signature.schema.json",
        &signature_schema_url,
    );
    println!(
        "Modified agent string for update: {}",
        modified_agent_string
    );

    agent.verify_self_signature().unwrap();
}

#[test]
fn test_validate_agent_json_raw() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    // Start the mock server and set the base URL
    let mock_server = MockServer::start();

    // Define schema URLs using the mock server base URL
    let header_schema_url = format!(
        "{}/schemas/header/v1/header.schema.json",
        mock_server.url("")
    );
    let agent_schema_url = format!("{}/schemas/agent/v1/agent.schema.json", mock_server.url(""));

    // Instantiate the EmbeddedSchemaResolver
    let resolver = EmbeddedSchemaResolver::new();

    // Mock the header schema
    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/v1/header.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS.get("schemas/header/v1/header.schema.json") {
                Some(schema_str) => schema_str,
                None => panic!("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    // Mock the agent schema
    let _agent_schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/schemas/agent/v1/agent.schema.json");
        then.status(200).body(
            match DEFAULT_SCHEMA_STRINGS.get("schemas/agent/v1/agent.schema.json") {
                Some(schema_str) => schema_str,
                None => panic!("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
            },
        );
    });

    // Corrected JSON data with all required fields and appropriate additional fields
    let json_data = r#"{
        "$schema": "http://localhost/schemas/header/v1/header.schema.json",
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "jacsVersionDate": "2024-05-02T00:00:00Z",
        "jacsOriginalVersion": "1.0.0",
        "jacsOriginalDate": "2024-05-02T00:00:00Z",
        "jacsAgentType": "human",
        "jacsServices": [
            {
                "serviceId": "service123",
                "serviceName": "Test Service",
                "serviceDescription": "A test service for validation purposes"
            }
        ],
        "jacsContacts": [
            {
                "contactId": "contact123",
                "contactType": "email",
                "contactDetails": "agent.smith@example.com"
            }
        ]
    }"#
    .to_string();

    // Correct the schema URLs in the JSON data strings
    let json_data = json_data
        .replace(
            "http://localhost/schemas/header/v1/header.schema.json",
            &header_schema_url,
        )
        .replace(
            "http://localhost/schemas/agent/v1/agent.schema.json",
            &agent_schema_url,
        );

    // Use the EmbeddedSchemaResolver to resolve the schema from memory
    let header_schema_value: serde_json::Value = serde_json::from_str(
        DEFAULT_SCHEMA_STRINGS
            .get("schemas/header/v1/header.schema.json")
            .expect("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
    )
    .expect("Failed to parse header schema into Value");

    let agent_schema_value: serde_json::Value = serde_json::from_str(
        DEFAULT_SCHEMA_STRINGS
            .get("schemas/agent/v1/agent.schema.json")
            .expect("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
    )
    .expect("Failed to parse agent schema into Value");

    let header_schema =
        JSONSchema::compile(&header_schema_value).expect("Failed to compile header schema");

    let agent_schema =
        JSONSchema::compile(&agent_schema_value).expect("Failed to compile agent schema");
}

#[test]
fn test_agent_creation_with_invalid_schema_urls() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    // Start the mock server and set the base URL
    let mock_server = MockServer::start();
    let base_url = mock_server.url("");

    // Define schema URLs using the mock server base URL
    let invalid_header_schema_url = format!("{}/invalid_header_schema.json", base_url);
    let invalid_agent_schema_url = format!("{}/invalid_agent_schema.json", base_url);

    // Instantiate the EmbeddedSchemaResolver with the mock server base URL
    let _resolver = EmbeddedSchemaResolver::new();

    let _schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/invalid_header_schema.json");
        then.status(404);
    });

    let _schema_mock_agent = mock_server.mock(|when, then| {
        when.method(GET).path("/invalid_agent_schema.json");
        then.status(404);
    });

    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let agent_creation_result = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        invalid_header_schema_url,
        invalid_agent_schema_url,
    );

    assert!(
        agent_creation_result.is_err(),
        "Agent creation should fail with invalid schema URLs"
    );
}

#[test]
fn test_agent_creation_with_different_schema_versions() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    // Test logic for different schema versions
    let mock_server = MockServer::start();
    let versions = vec!["v1", "v2", "v3"]; // Example versions

    for version in versions {
        let header_schema_url = format!(
            "{}/schemas/header/{}/header.schema.json",
            mock_server.url(""),
            version
        );
        let agent_schema_url = format!(
            "{}/schemas/agent/{}/agent.schema.json",
            mock_server.url(""),
            version
        );

        // Instantiate the EmbeddedSchemaResolver with the mock server base URL
        let _resolver = EmbeddedSchemaResolver::new();

        let _schema_mock = mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/schemas/header/{}/header.schema.json", version));
            then.status(200).body(
                match DEFAULT_SCHEMA_STRINGS.get("schemas/header/v1/header.schema.json") {
                    Some(schema_str) => schema_str,
                    None => panic!("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
                },
            );
        });

        let _schema_mock_agent = mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/schemas/agent/{}/agent.schema.json", version));
            then.status(200).body(
                match DEFAULT_SCHEMA_STRINGS.get("schemas/agent/v1/agent.schema.json") {
                    Some(schema_str) => schema_str,
                    None => panic!("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
                },
            );
        });

        let _agent = jacs::agent::Agent::new(
            &version.to_string(),
            &version.to_string(),
            header_schema_url.clone(),
            agent_schema_url.clone(),
        )
        .expect("Agent creation failed for provided version");
    }
}

// Test to ensure validation fails when required fields are missing
#[test]
fn test_agent_json_validation_missing_required_fields() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    let mock_server = MockServer::start();
    let base_url = mock_server.url("");

    let header_schema_url = format!("{}/schemas/header/v1/header.schema.json", base_url);
    let agent_schema_url = format!("{}/schemas/agent/v1/agent.schema.json", base_url);

    let json_data_missing_fields = r#"{
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsAgentType": "human",
        "jacsServices": [
            {
                "serviceId": "service123",
                "serviceName": "Test Service",
                "serviceDescription": "A test service for validation purposes"
            }
        ]
    }"#
    .replace("http://localhost", &base_url);

    let validation_errors = validate_json_data(
        &json_data_missing_fields,
        &header_schema_url,
        &agent_schema_url,
    );
    assert!(
        !validation_errors.is_empty(),
        "Validation should fail due to missing required fields"
    );
}

// Test to ensure validation does not fail when additional unexpected fields are present
#[test]
fn test_agent_json_validation_additional_unexpected_fields() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    let mock_server = MockServer::start();
    let base_url = mock_server.url("");

    let header_schema_url = format!("{}/schemas/header/v1/header.schema.json", base_url);
    let agent_schema_url = format!("{}/schemas/agent/v1/agent.schema.json", base_url);

    let json_data_with_unexpected_fields = r#"{
        "$schema": "http://localhost/schemas/header/v1/header.schema.json",
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "jacsAgentType": "human",
        "jacsServices": [
            {
                "serviceId": "service123",
                "serviceName": "Test Service",
                "serviceDescription": "A test service for validation purposes"
            }
        ],
        "jacsContacts": [
            {
                "contactId": "contact123",
                "contactType": "email",
                "contactDetails": "agent.smith@example.com"
            }
        ],
        "unexpectedField": "unexpectedValue"
    }"#
    .replace("http://localhost", &base_url);

    let validation_errors = validate_json_data(
        &json_data_with_unexpected_fields,
        &header_schema_url,
        &agent_schema_url,
    );
    assert!(
        validation_errors.is_empty(),
        "Validation should not fail due to additional unexpected fields: {:?}",
        validation_errors
    );
}

#[test]
fn test_agent_json_validation_incorrect_data_types() {
    // Set the environment variable to accept invalid certificates
    std::env::set_var("ACCEPT_INVALID_CERTS", "true");

    let mock_server = MockServer::start();
    let base_url = mock_server.url("");

    let header_schema_url = format!("{}/schemas/header/v1/header.schema.json", base_url);
    let agent_schema_url = format!("{}/schemas/agent/v1/agent.schema.json", base_url);

    let json_data_with_incorrect_types = r#"{
    "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
    "jacsVersion": "1.0.0",
    "jacsAgentType": "human",
    "jacsServices": [
        {
            "serviceId": "service123",
            "serviceName": "Test Service",
            "serviceDescription": "A test service for validation purposes"
        }
    ],
    "jacsContacts": [
        {
            "contactId": "contact123",
            "contactType": "email",
            "contactDetails": "agent.smith@example.com"
        }
    ],
    "unexpectedField": 123
}"#
    .replace("http://localhost", &base_url);

    let validation_errors = validate_json_data(
        &json_data_with_incorrect_types,
        &header_schema_url,
        &agent_schema_url,
    );
    assert!(
        !validation_errors.is_empty(),
        "Validation should fail due to incorrect data types for fields"
    );
}

fn validate_json_data(
    json_data: &str,
    header_schema_url: &str,
    agent_schema_url: &str,
) -> Vec<String> {
    let json_value: serde_json::Value =
        serde_json::from_str(json_data).expect("Failed to parse JSON data into a Value");
    let resolver = EmbeddedSchemaResolver::new();

    let header_schema_value: serde_json::Value = serde_json::from_str(match DEFAULT_SCHEMA_STRINGS
        .get("schemas/header/v1/header.schema.json")
    {
        Some(schema_str) => schema_str,
        None => panic!("Header schema string not found in DEFAULT_SCHEMA_STRINGS"),
    })
    .expect("Failed to parse header schema into Value");

    let agent_schema_value: serde_json::Value = serde_json::from_str(match DEFAULT_SCHEMA_STRINGS
        .get("schemas/agent/v1/agent.schema.json")
    {
        Some(schema_str) => schema_str,
        None => panic!("Agent schema string not found in DEFAULT_SCHEMA_STRINGS"),
    })
    .expect("Failed to parse agent schema into Value");

    let header_schema = JSONSchema::compile(
        &resolver
            .resolve(
                &header_schema_value,
                &Url::parse(&header_schema_url).expect("Failed to parse header schema URL"),
                "schemas/header/v1/header.schema.json",
            )
            .expect("Failed to resolve header schema"),
    )
    .expect("Failed to compile header schema");
    let agent_schema = JSONSchema::compile(
        &resolver
            .resolve(
                &agent_schema_value,
                &Url::parse(&agent_schema_url).expect("Failed to parse agent schema URL"),
                "schemas/agent/v1/agent.schema.json",
            )
            .expect("Failed to resolve agent schema"),
    )
    .expect("Failed to compile agent schema");

    let mut errors = Vec::new();

    if let Err(e) = header_schema.validate(&json_value) {
        errors.extend(e.into_iter().map(|err| err.to_string()));
    }

    if let Err(e) = agent_schema.validate(&json_value) {
        errors.extend(e.into_iter().map(|err| err.to_string()));
    }

    errors
}
