use std::fs;

#[test]
fn test_validate_agent_json() {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version);
    let json_data = fs::read_to_string("examples/agents/myagent.new.json").expect("REASON");
    let result = agent
        .expect("REASON")
        .create_agent_and_use(&json_data, false, None);
}
