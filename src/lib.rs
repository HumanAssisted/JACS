pub mod agent;
pub mod crypt;
pub mod loaders;
pub mod schema;
pub mod testtools;

use log::error;
use serde_json;

/// A function to validate an agent JSON string using the agent schema
pub fn validate_agent(json: &str, version: &str) -> Result<serde_json::Value, String> {
    // TODO , check_signature: bool
    let mut agent = match agent::Agent::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to validate Agent: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    agent.validate(json).map_err(|e| e.to_string())
}

pub fn create_agent() {}

pub fn update_agent() {
    // load original
    // update fields (new)
    // diff fields
    // update version
    // validate new
    // overwrite old
}

// create resource (omnipotent)
// create task
// create action
// create decision (omnipotent)
// update task from decision
// update task (version)
