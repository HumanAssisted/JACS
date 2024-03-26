use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::Agent;
use log::{debug, error, warn};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use std::env;

pub fn load_test_agent_one() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let result = agent.load_by_id("agent-one".to_string(), None);
    match result {
        Ok(_) => {
            debug!(
                "AGENT ONE LOADED {} {} ",
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

pub fn load_test_agent_two() -> Agent {
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();

    let mut agent = jacs::agent::Agent::new(&agent_version, &header_version, &signature_version)
        .expect("Agent schema should have instantiated");
    let result = agent.load_by_id("agent-two".to_string(), None);
    match result {
        Ok(_) => {
            debug!(
                "AGENT TWO LOADED {} {} ",
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

#[cfg(test)]
pub fn set_test_env_vars() {
    // to get reliable test outputs, use consistent keys
    env::set_var("JACS_DATA_DIRECTORY", "./examples/");
    env::set_var("JACS_KEY_DIRECTORY", "./examples/keys/");
    env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "agent-one.private.pem");
    env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "agent-one.public.pem");
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
}

#[cfg(test)]
pub fn load_local_document(filepath: &String) -> Result<String, Box<dyn Error>> {
    let current_dir = env::current_dir()?;
    let document_path: PathBuf = current_dir.join(filepath);
    let json_data = fs::read_to_string(document_path);
    match json_data {
        Ok(data) => {
            debug!("testing data {}", data);
            Ok(data.to_string())
        }
        Err(e) => {
            panic!("Failed to find file: {} {}", filepath, e);
        }
    }
}
