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
    let agent_string = fs::read_to_string("examples/raw/myagent.new.json").expect("REASON");
    let result = Agent::create_agent_and_load(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
        &agent_string,
    );

    if let Ok(mut agent) = result {
        println!("New Agent Created\n\n\n {} ", agent);
        // switch keys
        let private_key =
            fs::read("examples/keys/agent-two.private.pem").expect("Failed to read private key");
        let public_key =
            fs::read("examples/keys/agent-two.public.pem").expect("Failed to read public key");
        let key_algorithm = "RSA-PSS".to_string();
        let _ = agent.set_keys(private_key, public_key, &key_algorithm);
        let json_data = fs::read_to_string("examples/raw/mysecondagent.new.json").expect("REASON");
        let result = Agent::create_agent_and_load(
            &agent_version,
            &header_version,
            header_schema_url,
            document_schema_url,
            &json_data,
        );

        if let Ok(agent) = result {
            println!("New Agent2 Created\n\n\n {} ", agent);
        }
    }
}

#[test]
fn test_temp_validate_agent_creation() {
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let json_data = fs::read_to_string("./examples/raw/myagent.new.json").expect("REASON");
    let result = Agent::create_agent_and_load(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
        &json_data,
    );

    if let Ok(agent) = result {
        println!("New Agent Created\n\n\n {} ", agent);
    }
}

#[test]
fn test_temp_validate_agent_creation_save_and_load() {
    let header_schema_url = "http://localhost/schemas/header/v1/header.schema.json".to_string();
    let document_schema_url =
        "http://localhost/schemas/document/v1/document.schema.json".to_string();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let json_data = fs::read_to_string("./examples/raw/myagent.new.json").expect("REASON");
    let result = Agent::create_agent_and_load(
        &agent_version,
        &header_version,
        header_schema_url.clone(),
        document_schema_url.clone(),
        &json_data,
    );

    if let Ok(agent) = result {
        println!(
            "test_temp_validate_agent_creation_save_and_load Agent Created\n\n\n {} ",
            agent
        );
    }
}
