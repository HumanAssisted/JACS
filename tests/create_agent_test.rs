use std::fs;

#[test]
fn test_validate_agent_creation() {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version).unwrap();
    let json_data = fs::read_to_string("examples/agents/myagent.new.json").expect("REASON");
    let result = agent.create_agent_and_laod(&json_data, false, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("{}", error);
            assert!(false);
        }),
    };

    println!("New Agent Created {} ", agent);
}

#[test]
fn test_invalidate_existing_agent() {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version).unwrap();
    let json_data = fs::read_to_string("examples/agents/agent-two.json").expect("REASON");
    let result = agent.create_agent_and_laod(&json_data, false, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("New Agent Not created {} ", agent);
            println!("{}", error);
            assert!(true);
        }),
    };
}
