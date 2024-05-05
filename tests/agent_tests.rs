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
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
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
      "id": "agent123",
      "name": "Agent Smith",
      "role": "Field Agent",
      "version": "v1",
      "header_version": "v1",
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

    println!("JSON data for agent validation: {}", json_data);

    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.to_string(),
        agent_schema_url.to_string(),
    )
    .expect("Agent schema should have instantiated");
    let result = agent.load(&json_data);
    println!("Result of agent.load: {:?}", result);
    assert!(
        result.is_ok(),
        "Failed to validate agent JSON: {}",
        result.unwrap_err()
    );
}
