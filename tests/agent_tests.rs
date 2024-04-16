use jacs::agent::boilerplate::BoilerPlate;

mod utils;
use utils::load_local_document;

#[test]
fn test_update_agent_and_verify_versions() {
    // cargo test   --test schema_tests -- --nocapture
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let agentid =
        "49c48c7a-db1d-4e8c-9133-4c27f73737b8:06a9a142-ef51-4980-b29a-576ab2b3aadb".to_string();
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
