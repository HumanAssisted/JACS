use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::loaders::FileLoader;
mod utils;
use utils::{load_local_document, load_test_agent_one, load_test_agent_two, set_test_env_vars};

#[test]
fn test_load_agent_json() {
    set_test_env_vars();

    // cargo test   --test schema_tests -- --nocapture
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "6361aa35-ff7c-4b1d-b68a-a0b776caf535:5a54cddf-dadb-4393-b865-2c8cccb17c7f".to_string();
    let result = agent.load_by_id(agentid, None);

    match result {
        Ok(_) => {
            println!(
                "AGENT ID'd LOADED {} {} ",
                agent.get_id().unwrap(),
                agent.get_version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }
}

#[test]
fn test_update_agent_and_verify_versions() {
    set_test_env_vars();
    // cargo test   --test schema_tests -- --nocapture
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "6361aa35-ff7c-4b1d-b68a-a0b776caf535:5a54cddf-dadb-4393-b865-2c8cccb17c7f".to_string();
    let result = agent.load_by_id(agentid, None);

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
        load_local_document(&"examples/agent/agent-one-modified.json".to_string()).unwrap();

    match agent.update_self(&modified_agent_string) {
        Ok(_) => assert!(false),
        _ => {
            assert!(true);
            println!("NEW AGENT VERSION prevented");
        }
    };

    agent.verify_self_signature().unwrap();
}

#[test]
fn test_validate_agent_json_raw() {
    let json_data = r#"{
      "id": "agent123",
      "name": "Agent Smith",
      "role": "Field Agent"
    }"#
    .to_string();

    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let result = agent.load(&json_data);
    assert!(
        !result.is_ok(),
        "Correctly failed to validate myagent.json: {}",
        result.unwrap_err()
    );
}
