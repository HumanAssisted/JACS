use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::loaders::FileLoader;
mod utils;
use utils::{load_local_document, load_test_agent_one, load_test_agent_two, set_test_env_vars};

#[test]
fn test_load_agent_json() {
    // cargo test   --test schema_tests -- --nocapture
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let result = agent.load_by_id("agent-one".to_string(), None);

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

    let mut agent2 = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent should have instantiated");
    let _ = agent2
        .load_by_id("agent-two".to_string(), None)
        .expect("agent  two should ahve loaded");
    println!(
        "AGENT Two LOADED {} {} ",
        agent2.get_id().unwrap(),
        agent2.get_version().unwrap()
    );

    // println!(
    //     "AGENT Two keys {} {} ",
    //     agent2.private_key().unwrap(),
    //     agent2.public_key().unwrap()
    // );
}

#[test]
fn test_update_agent_and_verify_signature() {
    set_test_env_vars();
    // cargo test   --test schema_tests -- --nocapture
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let result = agent.load_by_id("agent-one".to_string(), None);

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

    let new_agent_version = agent.update_self(&modified_agent_string).unwrap();
    println!("NEW AGENT VERSION {}", new_agent_version);
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
