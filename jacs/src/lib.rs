use crate::agent::document::DocumentTraits;
use crate::shared::save_document;
use tracing::error;

use crate::agent::Agent;
use crate::agent::loaders::FileLoader;
use crate::schema::action_crud::create_minimal_action;
use crate::schema::agent_crud::create_minimal_agent;
use crate::schema::service_crud::create_minimal_service;
use crate::schema::task_crud::create_minimal_task;
use serde_json::Value;
use std::error::Error;
use std::path::Path;
use tracing::debug;

pub mod agent;
pub mod config;
pub mod crypt;
pub mod dns;
pub mod observability;
pub mod schema;
pub mod shared;
pub mod storage;

// #[cfg(feature = "cli")]
pub mod cli_utils;
// Re-export observability types for convenience
pub use observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    ResourceConfig, SamplingConfig, TracingConfig, TracingDestination, init_observability,
};

/// Initialize observability with a default configuration suitable for most applications.
/// This sets up file-based logging and metrics in the current directory.
pub fn init_default_observability() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::File {
                path: "./logs".to_string(),
            },
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: false,
            destination: MetricsDestination::File {
                path: "./metrics.txt".to_string(),
            },
            export_interval_seconds: Some(60),
            headers: None,
        },
        tracing: None,
    };

    init_observability(config).map(|_| ())
}

/// Initialize observability with custom configuration.
/// This is useful when you need specific logging/metrics destinations.
pub fn init_custom_observability(
    config: ObservabilityConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    init_observability(config).map(|_| ())
}

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
    debug!("[load_path_agent] Loading from path: {}", filepath);
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

    debug!("[load_path_agent] Extracted agent ID: {}", agent_id);

    // Pass ONLY the logical ID (without .json) to fs_agent_load
    let agent_string = agent
        .fs_agent_load(&agent_id.to_string()) // Pass ID string
        .map_err(|e| format!("agent file loading using ID '{}': {}", agent_id, e))
        .expect("Agent file loading failed");

    agent
        .load(&agent_string)
        .expect("agent loading from string failed");
    debug!(
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

/// Load an agent from a file path while controlling DNS strictness before validation runs.
pub fn load_agent_with_dns_strict(
    agentfile: String,
    dns_strict: bool,
) -> Result<agent::Agent, Box<dyn Error>> {
    let mut agent = get_empty_agent();
    agent.set_dns_strict(dns_strict);

    // Extract logical ID from provided path (expects .../agent/ID:VERSION.json)
    let agent_filename = std::path::Path::new(&agentfile)
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .ok_or("Could not extract filename from agent path")?;
    let agent_id = agent_filename
        .strip_suffix(".json")
        .ok_or("Agent filename does not end with .json")?;

    let agent_string = agent
        .fs_agent_load(&agent_id.to_string())
        .map_err(|e| format!("agent file loading using ID '{}': {}", agent_id, e))?;

    agent.load(&agent_string)?;
    Ok(agent)
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
