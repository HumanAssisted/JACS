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

pub mod a2a;
pub mod agent;
pub mod audit;
pub mod config;
pub mod crypt;
pub mod dns;
pub mod error;
pub mod health;
pub mod keystore;
pub mod mime;
pub mod observability;
pub mod paths;
pub mod rate_limit;
pub mod schema;
pub mod shared;
pub mod shutdown;
pub mod simple;
pub mod storage;
pub mod time_utils;
pub mod trust;
pub mod validation;

// #[cfg(feature = "cli")]
pub mod cli_utils;
// Re-export error types for convenience
pub use error::JacsError;

// Re-export health check types for convenience
pub use health::{
    ComponentHealth, HealthCheckResult, HealthStatus, health_check, network_health_check,
};

// Re-export audit types for convenience
pub use audit::{
    AuditOptions, AuditResult, AuditRisk, RiskCategory, RiskSeverity, audit, format_audit_report,
    print_audit_report,
};

// Re-export shutdown types for convenience
pub use shutdown::{ShutdownGuard, install_signal_handler, is_shutdown_requested, shutdown};

// Re-export rate limiting types for convenience
pub use rate_limit::{RateLimitConfig, RateLimiter};

// Re-export observability types for convenience
pub use observability::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    ResourceConfig, SamplingConfig, TracingConfig, TracingDestination, init_logging,
    init_observability,
};

// Re-export validation types for convenience
pub use validation::{
    AgentId, are_valid_uuid_parts, format_agent_id, is_valid_agent_id, normalize_agent_id,
    parse_agent_id, require_relative_path_safe, split_agent_id, validate_agent_id,
};

// Re-export time utilities for convenience
pub use time_utils::{
    backup_timestamp_suffix, now_rfc3339, now_timestamp, now_utc, parse_rfc3339,
    parse_rfc3339_to_timestamp, validate_signature_timestamp, validate_timestamp_not_expired,
    validate_timestamp_not_future,
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
        config::constants::JACS_AGENT_SCHEMA_VERSION,
        config::constants::JACS_HEADER_SCHEMA_VERSION,
        config::constants::JACS_SIGNATURE_SCHEMA_VERSION,
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
        .fs_agent_load(agent_id) // Pass ID string
        .map_err(|e| format!("Agent file loading failed for ID '{}': {}", agent_id, e))
        .expect("Agent file loading failed: could not load from storage");

    agent
        .load(&agent_string)
        .expect("Agent loading failed: could not parse agent data");
    debug!(
        "[load_path_agent] Agent loaded and validated successfully using ID: {}",
        agent_id
    );
    agent
}

pub fn load_agent(agentfile: Option<String>) -> Result<agent::Agent, Box<dyn Error>> {
    debug!("load_agent agentfile = {:?}", agentfile);
    if let Some(file) = agentfile {
        Ok(load_path_agent(file.to_string()))
    } else {
        Err("No agent file provided: specify an agent file path".into())
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
        .fs_agent_load(agent_id)
        .map_err(|e| format!("Agent file loading failed for ID '{}': {}", agent_id, e))?;

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
    task["jacsTaskCustomer"] = agent.signing_procedure(&task, None, "jacsTaskCustomer")?;

    // create document
    let embed = None;
    let docresult = agent.create_document_and_load(&task.to_string(), None, embed);

    save_document(agent, docresult, None, None, None, None)?;

    let task_value = agent.get_document(task["id"].as_str().unwrap())?.value;
    let validation_result = agent.schema.taskschema.validate(&task_value);
    match validation_result {
        Ok(_) => Ok(task_value.to_string()),
        Err(err) => {
            let schema_name = task_value
                .get("$schema")
                .and_then(|v| v.as_str())
                .unwrap_or("task.schema.json");
            let error_message = format!(
                "Task creation failed: {}",
                schema::format_schema_validation_error(&err, schema_name, &task_value)
            );
            error!("{}", error_message);
            Err(error_message.into())
        }
    }
}

// todo
pub fn update_task(_: String) -> Result<String, Box<dyn Error>> {
    // update document
    // validate
    Ok("".to_string())
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
