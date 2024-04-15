use crate::agent::Agent;
use std::env;
use std::error::Error;
use std::fs;

pub mod agent;
pub mod config;
pub mod crypt;
pub mod schema;

pub fn get_empty_agent() -> Agent {
    Agent::new(
        &env::var("JACS_AGENT_SCHEMA_VERSION").unwrap(),
        &env::var("JACS_HEADER_SCHEMA_VERSION").unwrap(),
        &env::var("JACS_SIGNATURE_SCHEMA_VERSION").unwrap(),
    )
    .expect("Failed to init Agent")
}

pub fn load_agent_by_id() -> Agent {
    let mut agent = get_empty_agent();
    let _ = agent.load_by_id(None, None);
    agent
}

/// TODO exlcude or modfiy for wasm context
fn load_path_agent(filepath: String) -> Agent {
    let mut agent = get_empty_agent();
    let agentstring = fs::read_to_string(filepath.clone()).expect("agent file loading");
    let _ = agent.load(&agentstring);
    agent
}

pub fn load_agent(agentfile: Option<String>) -> Result<agent::Agent, Box<dyn Error>> {
    if let Some(file) = agentfile {
        return Ok(load_path_agent(file.to_string()));
    } else {
        return Ok(load_agent_by_id());
    };
}
