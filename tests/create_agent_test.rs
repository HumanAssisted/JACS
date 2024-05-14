use jacs::agent::Agent;
use std::fs;

mod utils;

#[test]
fn test_validate_agent_creation() {
    // RUST_BACKTRACE=1 cargo test create_agent_tests -- --test test_validate_agent_creation
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let agent_string = fs::read_to_string("examples/raw/myagent.new.json")
        .expect("Failed to read agent JSON data");
    let mut agent = Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
    )
    .unwrap();
    let result = agent.create_agent_and_load(&agent_string);

    if let Ok(mut agent) = result {
        dbg!("New Agent Created", &agent);
        // switch keys
        let private_key =
            fs::read("examples/keys/agent-two.private.pem").expect("Failed to read private key");
        let public_key =
            fs::read("examples/keys/agent-two.public.pem").expect("Failed to read public key");
        let key_algorithm = "RSA-PSS".to_string();
        agent
            .set_keys(private_key, public_key, &key_algorithm)
            .expect("Failed to set keys for agent");
        let json_data = fs::read_to_string("examples/raw/mysecondagent.new.json")
            .expect("Failed to read second agent JSON data");
        agent
            .create_agent_and_load(&json_data)
            .expect("Failed to create and load second agent");
        dbg!("New Agent2 Created", &agent);
    }
}

#[test]
fn test_temp_validate_agent_creation() {
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let json_data = fs::read_to_string("./examples/raw/myagent.new.json")
        .expect("Failed to read agent JSON data");
    let mut agent = Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
    )
    .unwrap();
    agent
        .create_agent_and_load(&json_data)
        .expect("Failed to create and load agent");
    dbg!("New Agent Created", &agent);
}

#[test]
fn test_temp_validate_agent_creation_save_and_load() {
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let json_data = fs::read_to_string("./examples/raw/myagent.new.json")
        .expect("Failed to read agent JSON data");
    let mut agent = Agent::new(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
    )
    .unwrap();
    agent
        .create_agent_and_load(&json_data)
        .expect("Failed to create and load agent");
    dbg!(
        "test_temp_validate_agent_creation_save_and_load Agent Created",
        &agent
    );
}
