use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::Agent;

pub fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version)
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
    agent
}
