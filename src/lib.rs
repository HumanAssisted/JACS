use crate::agent::document::DocumentTraits;
use crate::shared::save_document;
use log::error;

use crate::agent::Agent;
use crate::schema::action_crud::create_minimal_action;
use crate::schema::agent_crud::create_minimal_agent;
use crate::schema::service_crud::create_minimal_service;
use crate::schema::task_crud::create_minimal_task;
use crate::storage::jenv::get_required_env_var;
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
pub mod storage;

pub fn get_empty_agent() -> Agent {
    Agent::new(
        &get_required_env_var("JACS_AGENT_SCHEMA_VERSION", true)
            .expect("JACS_AGENT_SCHEMA_VERSION must be set"),
        &get_required_env_var("JACS_HEADER_SCHEMA_VERSION", true)
            .expect("JACS_HEADER_SCHEMA_VERSION must be set"),
        &get_required_env_var("JACS_SIGNATURE_SCHEMA_VERSION", true)
            .expect("JACS_SIGNATURE_SCHEMA_VERSION must be set"),
    )
    .expect("Failed to init Agent")
}

pub fn load_agent_by_id() -> Agent {
    let mut agent = get_empty_agent();
    agent.load_by_id(None, None).expect("agent.load_by_id: ");
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

pub fn create_task(
    agent: &mut Agent,
    name: String,
    description: String,
) -> Result<String, Box<dyn Error>> {
    let mut actions: Vec<Value> = Vec::new();
    let action = create_minimal_action(&name, &description, None, None);
    actions.push(action);
    let mut task = create_minimal_task(Some(actions), None, None, None)?;
    task["jacsTaskCustomer"] =
        agent.signing_procedure(&task, None, &"jacsTaskCustomer".to_string())?;

    // create document
    let embed = None;
    let docresult = agent.create_document_and_load(&task.to_string(), None, embed);

    save_document(agent, docresult, None, None, None, None)?;

    let task_value = agent
        .get_document(&task["id"].as_str().unwrap().to_string())?
        .value;
    let validation_result = agent.schema.taskschema.validate(&task_value);
    match validation_result {
        Ok(_) => Ok(task_value.to_string()),
        Err(error) => {
            error!("error validating task");
            let error_message = error.to_string();
            Err(error_message.into())
        }
    }
}

// todo
pub fn update_task(previoustask: String) -> Result<String, Box<dyn Error>> {
    // update document
    // validate
    return Ok("".to_string());
}
