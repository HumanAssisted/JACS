use jacs::loaders::testloader::TestFileLoader;
use std::fs;

// #[test]
// fn test_validate_agent_json() {
//     let json_data = fs::read_to_string("examples/myagent.json");

//     match json_data {
//         Ok(data) => {
//             println!("testing data {}", data);
//             let result = jacs::validate_agent(&data, "v1");
//             assert!(
//                 result.is_ok(),
//                 "Failed to validate myagent.json: {}",
//                 result.unwrap_err()
//             );
//         }
//         Err(e) => {
//             panic!("Failed to read 'examples/myagent.json': {}", e);
//         }
//     }
// }

#[test]
fn test_load_agent_json() {
    // cargo test   --test schema_tests -- --nocapture
    let loader = TestFileLoader;
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(loader, &agent_version, &header_version)
        .expect("Agent should have instantiated");
    let result = agent.load_by_id("agent-one".to_string(), None);

    match result {
        Ok(_) => {
            println!(
                "AGENT LOADED {} {} ",
                agent.id().unwrap(),
                agent.version().unwrap()
            );
        }
        Err(e) => {
            eprintln!("Error loading agent: {}", e);
            panic!("Agent loading failed");
        }
    }

    let loader2 = TestFileLoader;
    let mut agent2 = jacs::agent::Agent::new(loader2, &agent_version, &header_version)
        .expect("Agent should have instantiated");
    let _ = agent2
        .load_by_id("agent-two".to_string(), None)
        .expect("agent should ahve loaded");
    println!(
        "AGENT Two LOADED {} {} ",
        agent2.id().unwrap(),
        agent2.version().unwrap()
    );

    println!(
        "AGENT Two keys {} {} ",
        agent2.private_key().unwrap(),
        agent2.public_key().unwrap()
    );
}

#[test]
fn test_validate_agent_json_raw() {
    let json_data = r#"{
      "id": "agent123",
      "name": "Agent Smith",
      "role": "Field Agent"
    }"#
    .to_string();

    let loader = TestFileLoader;
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let mut agent = jacs::agent::Agent::new(loader, &agent_version, &header_version)
        .expect("Agent should have instantiated");
    let result = agent.load(&json_data);
    assert!(
        !result.is_ok(),
        "Correctly failed to validate myagent.json: {}",
        result.unwrap_err()
    );
    // match result {
    //     Ok(_) => {
    //         println!(
    //             "AGENT LOADED {} {} ",
    //             agent.id().unwrap(),
    //             agent.version().unwrap()
    //         );
    //     }
    //     Err(e) => {
    //         eprintln!("Error loading agent: {}", e);
    //         panic!("Agent loading failed");
    //     }
    // }

    // println!("testing data {}", json_data);
    // let result = jacs::validate_agent(&json_data, "v1");
    // assert!(
    //     !result.is_ok(),
    //     "Correctly failed to validate myagent.json: {}",
    //     result.unwrap_err()
    // );
}
