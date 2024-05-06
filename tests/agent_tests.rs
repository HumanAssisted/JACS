use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;
use jsonschema::JSONSchema;

mod utils;
use utils::load_local_document;

#[test]
fn test_update_agent_and_verify_versions() {
    let mock_server = MockServer::start();
    let base_url = mock_server.url("");
    let header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let agent_schema_url = format!("{}/schemas/agent/mock_version/agent.schema.json", base_url);
    let agreement_schema_url = format!(
        "{}/schemas/components/agreement/mock_version/agreement.schema.json",
        base_url
    );
    let files_schema_url = format!(
        "{}/schemas/components/files/mock_version/files.schema.json",
        base_url
    );
    let signature_schema_url = format!(
        "{}/schemas/components/signature/mock_version/signature.schema.json",
        base_url
    );

    let _schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/mock_version/header.schema.json");
        then.status(200)
            .body(include_str!("../schemas/header/v1/header.schema.json"));
    });

    let _schema_mock_agent = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/agent/mock_version/agent.schema.json");
        then.status(200)
            .body(include_str!("../schemas/agent/v1/agent.schema.json"));
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

    let modified_agent_string = include_str!("../examples/raw/modified-agent-for-updating.json")
        .replace(
            "https://hai.ai/schemas/agent/v1/agent-schema.json",
            &agent_schema_url,
        )
        .replace(
            "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json",
            &agreement_schema_url,
        )
        .replace(
            "https://hai.ai/schemas/components/files/v1/files.schema.json",
            &files_schema_url,
        )
        .replace(
            "https://hai.ai/schemas/components/signature/v1/signature.schema.json",
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
    let mock_server = MockServer::start();
    let base_url = mock_server.url("");
    let header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let agent_schema_url = format!("{}/schemas/agent/mock_version/agent.schema.json", base_url);

    let _schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/mock_version/header.schema.json");
        then.status(200)
            .body(include_str!("../schemas/header/v1/header.schema.json"));
    });

    let _schema_mock_agent = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/agent/mock_version/agent.schema.json");
        then.status(200)
            .body(include_str!("../schemas/agent/v1/agent.schema.json"));
    });

    let _schema_mock_agreement = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/agreement/mock_version/agreement.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/agreement/v1/agreement.schema.json"
        ));
    });

    let _schema_mock_files = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/files/mock_version/files.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/files/v1/files.schema.json"
        ));
    });

    let _schema_mock_signature = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/components/signature/mock_version/signature.schema.json");
        then.status(200).body(include_str!(
            "../schemas/components/signature/v1/signature.schema.json"
        ));
    });

    let json_data = r#"{
  "$schema": "http://localhost/schemas/agent/mock_version/agent.schema.json",
  "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
  "jacsVersion": "1.0.0",
  "jacsVersionDate": "2024-05-02T08:38:43Z",
  "jacsOriginalVersion": "1.0.0",
  "jacsOriginalDate": "2024-05-02T08:38:43Z",
  "jacsAgentType": "human",
  "jacsServices": [],
  "jacsContacts": [],
  "jacsSignature": {
    "$schema": "http://localhost/schemas/components/signature/mock_version/signature.schema.json",
    "type": "signature",
    "signatureValue": "test_signature_value"
  },
  "jacsRegistration": {
    "$schema": "http://localhost/schemas/components/registration/mock_version/registration.schema.json",
    "type": "registration",
    "registrationValue": "test_registration_value"
  },
  "jacsAgreement": {
    "$schema": "http://localhost/schemas/components/agreement/mock_version/agreement.schema.json",
    "type": "agreement",
    "agreementValue": "test_agreement_value"
  },
  "jacsAgreementHash": "test_agreement_hash",
  "jacsPreviousVersion": "0.9.0",
  "jacsSha256": "test_sha256",
  "jacsFiles": [
    {
      "$schema": "http://localhost/schemas/components/files/mock_version/files.schema.json",
      "fileId": "file123",
      "fileName": "Test File",
      "fileDescription": "A test file for validation purposes"
    }
  ]
}"#.to_string();

    // Parse the JSON data into a Value to ensure it is correctly formatted
    let json_value: serde_json::Value =
        serde_json::from_str(&json_data).expect("Failed to parse JSON data into a Value");

    println!("JSON data as a string before loading: {}", json_data);
    println!("JSON data as a Value before loading: {:?}", json_value);

    // Ensure the JSON string is not empty and is a valid JSON object before attempting to load
    assert!(!json_data.is_empty(), "JSON data string is empty");
    assert!(
        json_value.is_object(),
        "JSON data is not a valid JSON object"
    );

    // Additional logging to confirm the JSON Value is not Null and is correctly structured
    println!("Confirming JSON Value is not Null and is correctly structured before validation:");
    println!("{:?}", json_value);

    // Compile the header schema from the mock server URL
    let header_schema_content = include_str!("../schemas/header/v1/header.schema.json");
    let header_schema_json: serde_json::Value = serde_json::from_str(header_schema_content)
        .expect("Failed to parse header schema content into JSON");
    let header_schema = JSONSchema::compile(&header_schema_json)
        .expect("Failed to compile header schema from content");

    // Compile the agent schema from the mock server URL
    let agent_schema_content = include_str!("../schemas/agent/v1/agent.schema.json");
    let agent_schema_json: serde_json::Value = serde_json::from_str(agent_schema_content)
        .expect("Failed to parse agent schema content into JSON");
    let agent_schema = JSONSchema::compile(&agent_schema_json)
        .expect("Failed to compile agent schema from content");

    // Validate the JSON data against the header and agent schemas
    let header_errors: Vec<String> = match header_schema.validate(&json_value) {
        Ok(_) => vec![],
        Err(errors) => errors
            .into_iter()
            .map(|e| {
                let error_message = format!(
                    "Error: {}, Instance: {}, Schema path: {}",
                    e.to_string(),
                    e.instance_path,
                    e.schema_path
                );
                println!("{}", error_message);
                error_message
            })
            .collect(),
    };
    let agent_errors: Vec<String> = match agent_schema.validate(&json_value) {
        Ok(_) => vec![],
        Err(errors) => errors
            .into_iter()
            .map(|e| {
                let error_message = format!(
                    "Error: {}, Instance: {}, Schema path: {}",
                    e.to_string(),
                    e.instance_path,
                    e.schema_path
                );
                println!("{}", error_message);
                error_message
            })
            .collect(),
    };

    // Assert that there are no validation errors for both header and agent schemas
    assert!(
        header_errors.is_empty(),
        "Header schema validation errors: {:?}",
        header_errors
    );
    assert!(
        agent_errors.is_empty(),
        "Agent schema validation errors: {:?}",
        agent_errors
    );
}

#[test]
fn test_agent_creation_with_invalid_schema_urls() {
    let mock_server = MockServer::start();
    let invalid_header_schema_url = format!("{}/invalid_header_schema.json", mock_server.url(""));
    let invalid_agent_schema_url = format!("{}/invalid_agent_schema.json", mock_server.url(""));

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

        let _schema_mock = mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/schemas/header/{}/header.schema.json", version));
            then.status(200)
                .body(include_str!("../schemas/header/v1/header.schema.json"));
        });

        let _schema_mock_agent = mock_server.mock(|when, then| {
            when.method(GET)
                .path(format!("/schemas/agent/{}/agent.schema.json", version));
            then.status(200)
                .body(include_str!("../schemas/agent/v1/agent.schema.json"));
        });

        let agent = jacs::agent::Agent::new(
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
    .to_string();

    let validation_errors = validate_json_data(
        &json_data_missing_fields,
        "../schemas/header/v1/header.schema.json",
        "../schemas/agent/v1/agent.schema.json",
    );
    assert!(
        !validation_errors.is_empty(),
        "Validation should fail due to missing required fields"
    );
}

// Test to ensure validation does not fail when additional unexpected fields are present
#[test]
fn test_agent_json_validation_additional_unexpected_fields() {
    let json_data_with_unexpected_fields = r#"{
        "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
        "jacsVersion": "1.0.0",
        "unexpectedField": "unexpectedValue"
    }"#
    .to_string();

    let validation_errors = validate_json_data(
        &json_data_with_unexpected_fields,
        "../schemas/header/v1/header.schema.json",
        "../schemas/agent/v1/agent.schema.json",
    );
    assert!(
        validation_errors.is_empty(),
        "Validation should not fail due to additional unexpected fields"
    );
}

#[test]
fn test_agent_json_validation_incorrect_data_types() {
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
    .to_string();

    let validation_errors = validate_json_data(
        &json_data_with_incorrect_types,
        "../schemas/header/v1/header.schema.json",
        "../schemas/agent/v1/agent.schema.json",
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
    let header_schema = JSONSchema::compile(
        &serde_json::from_str(include_str!("../schemas/header/v1/header.schema.json"))
            .expect("Failed to parse header schema"),
    )
    .expect("Failed to compile header schema");
    let agent_schema = JSONSchema::compile(
        &serde_json::from_str(include_str!("../schemas/agent/v1/agent.schema.json"))
            .expect("Failed to parse agent schema"),
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
