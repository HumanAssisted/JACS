use jacs::agent::Agent;

pub fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version)
        .expect("Agent schema should have instantiated");
    let _ = agent.load_by_id("agent-one".to_string(), None);
    agent
}
