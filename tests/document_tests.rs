use jacs::agent::boilerplate::BoilerPlate;
use jacs::tests::load_test_agent_one;

#[test]
fn test_load_agent_json() {
    // cargo test   --test schema_tests -- --nocapture
    agent = load_test_agent_one();
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

    let mut agent2 = jacs::agent::Agent::new(&agent_version, &header_version)
        .expect("Agent should have instantiated");
    let _ = agent2
        .load_by_id("agent-two".to_string(), None)
        .expect("agent should ahve loaded");
    println!(
        "AGENT Two LOADED {} {} ",
        agent2.get_id().unwrap(),
        agent2.get_version().unwrap()
    );
}
