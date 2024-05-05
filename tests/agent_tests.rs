use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::boilerplate::BoilerPlate;

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

    let modified_agent_string =
        load_local_document(&"examples/raw/modified-agent-for-updating.json".to_string()).unwrap();

    println!(
        "Modified agent string for update: {}",
        modified_agent_string
    );

    match agent.update_self(&modified_agent_string) {
        Ok(_) => assert!(true),
        _ => {
            assert!(false);
            println!("NEW AGENT VERSION prevented");
        }
    };

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

    let json_data = r#"{
      "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
      "jacsId": "48d074ec-84e2-4d26-adc5-0b2253f1e8ff",
      "jacsVersion": "1.0.0",
      "jacsVersionDate": "2024-05-02T08:38:43Z",
      "jacsOriginalVersion": "1.0.0",
      "jacsOriginalDate": "2024-05-02T08:38:43Z",
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
      "jacsSignature": {
        "type": "signature",
        "signatureValue": "test_signature_value"
      },
      "jacsRegistration": {
        "type": "registration",
        "registrationValue": "test_registration_value"
      },
      "jacsAgreement": {
        "type": "agreement",
        "agreementValue": "test_agreement_value"
      },
      "jacsAgreementHash": "test_agreement_hash",
      "jacsPreviousVersion": "0.9.0",
      "jacsSha256": "test_sha256",
      "jacsFiles": [
        {
          "fileId": "file123",
          "fileName": "Test File",
          "fileDescription": "A test file for validation purposes"
        }
      ]
    }"#
    .to_string();

    // Parse the JSON data into a Value to ensure it is correctly formatted
    let json_value: serde_json::Value =
        serde_json::from_str(&json_data).expect("Failed to parse JSON data into a Value");

    println!("JSON data as a string before loading: {}", json_data);
    println!("JSON data as a Value before loading: {:?}", json_value);

    // Additional logging to confirm the JSON Value is not Null and is correctly structured
    println!("Confirming JSON Value is not Null and is correctly structured before validation:");
    println!("{:?}", json_value);

    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.to_string(),
        agent_schema_url.to_string(),
    )
    .expect("Agent schema should have instantiated");
    println!(
        "Agent instantiated with schema URLs: header - {}, agent - {}",
        header_schema_url, agent_schema_url
    );

    // Ensure the JSON string is not empty and is a valid JSON object before attempting to load
    assert!(!json_data.is_empty(), "JSON data string is empty");
    assert!(
        json_value.is_object(),
        "JSON data is not a valid JSON object"
    );

    let result = agent.load(&json_data);
    println!("Result of agent.load: {:?}", result);
    if let Err(e) = &result {
        println!("Detailed validation errors: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "Failed to validate agent JSON: {:?}",
        result
    );
}
