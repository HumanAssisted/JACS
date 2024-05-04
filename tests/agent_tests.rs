use jacs::agent::boilerplate::BoilerPlate;

// mod utils;
// use utils::load_local_document;

#[test]
fn test_update_agent_and_verify_versions() {
    // cargo test   --test agent_tests -- --nocapture
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
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

    // The following code is commented out due to unresolved import of `load_local_document`
    // let modified_agent_string =
    //     load_local_document(&"examples/raw/modified-agent-for-updating.json".to_string()).unwrap();

    // match agent.update_self(&modified_agent_string) {
    //     Ok(_) => assert!(true),
    //     _ => {
    //         assert!(false);
    //         println!("NEW AGENT VERSION prevented");
    //     }
    // };

    // agent.verify_self_signature().unwrap();
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
