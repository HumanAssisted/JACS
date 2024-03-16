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

#[cfg(test)]
mod tests {

    use super::*;
    use jacs::testtools::FileLoader;

    #[test]
    fn test_load_agent_json() {
        // cargo test   --test schema_tests -- --nocapture

        let version = "v1";
        let mut agent = jacs::agent::Agent::new(version).expect("Agent should have instantiated");
        let _ = agent.load("b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14".to_string(),  None).expect("agent should ahve loaded");
        println!("AGENT LOADED {} {} ", agent.id().unwrap(), agent.version().unwrap());

    }
}


#[cfg(test)]
mod testtwo {


    #[test]
    fn test_load_agent_json_no_file_loader() {
        // cargo test   --test schema_tests -- --nocapture

        let version = "v1";
        let mut agent = jacs::agent::Agent::new(version).expect("Agent should have instantiated");
        let _ = agent.load("b6a7fcb4-a6e0-413b-9f5d-48a42a8e9d14".to_string(),  None).expect("agent should ahve loaded");
        println!("AGENT LOADED {} {} ", agent.id().unwrap(), agent.version().unwrap());

    }
}



// #[test]
// fn test_validate_agent_json_raw() {
//     let json_data = r#"{
//       "id": "agent123",
//       "name": "Agent Smith",
//       "role": "Field Agent"
//     }"#;

//     println!("testing data {}", json_data);
//     let result = jacs::validate_agent(&json_data, "v1");
//     assert!(
//         !result.is_ok(),
//         "Correctly failed to validate myagent.json: {}",
//         result.unwrap_err()
//     );
// }
