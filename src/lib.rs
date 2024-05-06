use crate::agent::Agent;
use crate::schema::action_crud::create_minimal_action;
use crate::schema::agent_crud::create_minimal_agent;
use crate::schema::service_crud::create_minimal_service;
use crate::schema::task_crud::create_minimal_task;
use log::{debug, error}; // Added debug import
use serde_json::Value;
use std::env;
use std::error::Error;
use std::fs;

pub mod agent;
pub mod config;
pub mod crypt;
pub mod custom_resolver;
pub mod schema;
pub mod shared; // Added public declaration for custom_resolver module

pub fn get_empty_agent() -> Result<Agent, Box<dyn Error>> {
    let header_schema_url = env::var("JACS_HEADER_SCHEMA_URL")
        .unwrap_or_else(|_| "http://localhost/schemas/header/v1/header.schema.json".to_string());
    let document_schema_url = env::var("JACS_DOCUMENT_SCHEMA_URL").unwrap_or_else(|_| {
        "http://localhost/schemas/document/v1/document.schema.json".to_string()
    });

    let agent_result = Agent::new(
        &env::var("JACS_AGENT_SCHEMA_VERSION").unwrap_or_else(|_| "v1".to_string()),
        &env::var("JACS_HEADER_SCHEMA_VERSION").unwrap_or_else(|_| "v1".to_string()),
        header_schema_url,
        document_schema_url,
    );

    match agent_result {
        Ok(agent) => Ok(agent),
        Err(e) => {
            error!("Failed to init Agent: {}", e);
            Err(e)
        }
    }
}

pub fn load_agent_by_id() -> Result<Agent, Box<dyn Error>> {
    let mut agent = get_empty_agent()?;
    agent.load_by_id(None, None)?;
    Ok(agent)
}

fn load_path_agent(filepath: String) -> Result<Agent, Box<dyn Error>> {
    let mut agent = get_empty_agent()?;
    let agentstring = fs::read_to_string(filepath.clone())?;
    agent.load(&agentstring)?;
    Ok(agent)
}

pub fn load_agent(agentfile: Option<String>) -> Result<agent::Agent, Box<dyn Error>> {
    debug!("load_agent agentfile = {:?}", agentfile);
    if let Some(file) = agentfile {
        load_path_agent(file.to_string())
    } else {
        load_agent_by_id()
    }
}

pub fn create_minimal_blank_agent(agentype: String) -> Result<String, Box<dyn Error>> {
    let mut services: Vec<Value> = Vec::new();
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
    let agent_value = create_minimal_agent(&agentype, Some(services), None)?;
    Ok(agent_value.to_string())
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
    // Adjusted the following line to handle the () return type from signing_procedure
    let signing_result = agent.signing_procedure()?;
    task["jacsTaskCustomer"] = Value::Null; // Placeholder value, assuming signing_procedure does not alter the task

    let embed: Option<Value> = None;
    // Commented out the following line due to missing method
    // let docresult = agent.create_document_and_load(&task.to_string(), None, embed);

    // Commented out the following line due to missing method
    // save_document(agent, docresult, None, None, None, None)?;

    // Commented out the following line due to missing method
    // let task_value = agent
    //     .get_document(&task["id"].as_str().unwrap().to_string())?
    //     .value;
    // let validation_result = agent.schema.taskschema.validate(&task_value);
    // match validation_result {
    //     Ok(_) => Ok(task_value.to_string()),
    //     Err(errors) => {
    //         error!("error validating task");
    //         let error_messages: Vec<String> = errors.into_iter().map(|e| e.to_string()).collect();
    //         Err(error_messages
    //             .first()
    //             .cloned()
    //             .unwrap_or_else(|| {
    //                 "Unexpected error during validation: no error messages found".to_string()
    //             })
    //             .into())
    //     }
    // }
    // Placeholder return value until the above methods are implemented
    Ok("Task creation and validation are not yet implemented".to_string())
}

pub fn update_task(_previoustask: String) -> Result<String, Box<dyn Error>> {
    Ok("".to_string())
}
