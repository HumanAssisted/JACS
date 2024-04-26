use crate::agent::Agent;
use crate::schema::agent_crud::create_minimal_agent;
use crate::schema::service_crud::create_minimal_service;
use log::debug;
use serde_json::Value;
use std::env;
use std::error::Error;
use std::fs;

pub mod agent;
pub mod config;
pub mod crypt;
pub mod schema;
pub mod shared;

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
    agent.load_by_id(None, None).expect("agent.load_by_id. ");
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
    debug!("load_agent agentfile = {:?}", agentfile);
    if let Some(file) = agentfile {
        return Ok(load_path_agent(file.to_string()));
    } else {
        return Ok(load_agent_by_id());
    };
}

pub fn create_minimal_blank_agent(agentype: String) -> Result<String, Box<dyn Error>> {
    let mut services: Vec<Value> = Vec::new();
    // create service
    let service_description = "Describe a service the agent provides";
    let success_description = "Describe a success of the service the agent provides";
    let failure_description = "Describe what failure is of the service the agent provides";
    let service = create_minimal_service(
        service_description,
        success_description,
        failure_description,
        None,
        None,
    )?;
    services.push(service);
    // add service
    let agent_value = create_minimal_agent(&agentype, Some(services), None)?;
    return Ok(agent_value.to_string());
}

pub fn create_task() -> Result<String, Box<dyn Error>> {
    // sign doc at "jacsTaskCustomer"

    // validate and save
    // sign document
    return Ok("".to_string());
}

pub fn update_task(previoustask: String) -> Result<String, Box<dyn Error>> {
    // update document
    // validate
    return Ok("".to_string());
}
