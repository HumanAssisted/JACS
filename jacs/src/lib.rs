use crate::agent::document::DocumentTraits;
use crate::shared::save_document;
use log::error;

use crate::agent::Agent;
use crate::agent::loaders::FileLoader;
use crate::schema::action_crud::create_minimal_action;
use crate::schema::agent_crud::create_minimal_agent;
use crate::schema::service_crud::create_minimal_service;
use crate::schema::task_crud::create_minimal_task;
use log::debug;
use serde_json::Value;
use std::error::Error;
use std::path::Path;

pub mod agent;
pub mod cli_utils;
pub mod config;
pub mod crypt;
pub mod schema;
pub mod shared;
pub mod storage;

/// Creates an empty agent struct with default schema versions.
pub fn get_empty_agent() -> Agent {
    // Use expect as Result handling happens elsewhere or isn't needed here.
    Agent::new(
        &config::constants::JACS_AGENT_SCHEMA_VERSION.to_string(),
        &config::constants::JACS_HEADER_SCHEMA_VERSION.to_string(),
        &config::constants::JACS_SIGNATURE_SCHEMA_VERSION.to_string(),
    )
    .expect("Failed to init Agent in get_empty_agent") // Panic if Agent::new fails
}

/// Load agent using specific path
fn load_path_agent(filepath: String) -> Agent {
    println!("[load_path_agent] Loading from path: {}", filepath);
    let mut agent = get_empty_agent(); // Assuming get_empty_agent() returns Agent directly

    // Extract filename (e.g., "ID:VERSION.json") from the full path
    let agent_filename = Path::new(&filepath)
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .map(|s| s.to_string())
        .expect("Could not extract filename from agent path");

    // Strip the .json suffix to get the logical ID
    let agent_id = agent_filename
        .strip_suffix(".json")
        .expect("Agent filename does not end with .json");

    println!("[load_path_agent] Extracted agent ID: {}", agent_id);

    // Pass ONLY the logical ID (without .json) to fs_agent_load
    let agent_string = agent
        .fs_agent_load(&agent_id.to_string()) // Pass ID string
        .map_err(|e| format!("agent file loading using ID '{}': {}", agent_id, e))
        .expect("Agent file loading failed");

    agent
        .load(&agent_string)
        .expect("agent loading from string failed");
    println!(
        "[load_path_agent] Agent loaded and validated successfully using ID: {}",
        agent_id
    );
    agent
}

pub fn load_agent(agentfile: Option<String>) -> Result<agent::Agent, Box<dyn Error>> {
    debug!("load_agent agentfile = {:?}", agentfile);
    if let Some(file) = agentfile {
        return Ok(load_path_agent(file.to_string()));
    } else {
        return Err("No agent file provided".into());
    }
}

/// Creates a minimal agent JSON string with a default service.
/// Optionally accepts descriptions for the default service.
pub fn create_minimal_blank_agent(
    agentype: String,
    service_desc: Option<String>,
    success_desc: Option<String>,
    failure_desc: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let mut services: Vec<Value> = Vec::new();

    // Use provided descriptions or fall back to defaults.
    let service_description =
        service_desc.unwrap_or_else(|| "Describe a service the agent provides".to_string());
    let success_description = success_desc
        .unwrap_or_else(|| "Describe a success of the service the agent provides".to_string());
    let failure_description = failure_desc.unwrap_or_else(|| {
        "Describe what failure is of the service the agent provides".to_string()
    });

    let service = create_minimal_service(
        &service_description,
        &success_description,
        &failure_description,
        None,
        None,
    )
    .map_err(|e| {
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)) as Box<dyn Error>
    })?;

    services.push(service);

    // Add service
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
pub fn update_task(_: String) -> Result<String, Box<dyn Error>> {
    // update document
    // validate
    return Ok("".to_string());
}

// lets move these here

/*
create_config() - Create configuration (missing)
verify_agent() - Verify agent integrity (missing)
verify_document() - Verify document integrity (missing)
verify_signature() - Verify signature (missing)
update_agent() - Update existing agent (missing)
update_document() - Update existing document (missing)


*/
