pub mod crypt;
pub mod schema;

use log::error;

/// A function to validate an agent JSON string using the agent schema
pub fn validate_agent(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let mut agent = match schema::agent::Agent::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to validate Agent: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    agent.validate(json).map_err(|e| e.to_string())
}

/// A function to validate an action JSON string using the action schema
pub fn validate_action(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let action = match schema::action::Action::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create Action: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    action.validate(json).map_err(|e| e.to_string())
}

/// A function to validate an task JSON string using the task schema
pub fn validate_task(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let task = match schema::task::Task::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create Task: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    task.validate(json).map_err(|e| e.to_string())
}

/// A function to validate an decision JSON string using the decision schema
pub fn validate_decision(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let decision = match schema::decision::Decision::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create Decision: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    decision.validate(json).map_err(|e| e.to_string())
}

pub fn validate_resource(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let resource = match schema::resource::Resource::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create Resource: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    resource.validate(json).map_err(|e| e.to_string())
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
