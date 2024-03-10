pub mod schema;
use log::error;

/// A function to validate an agent JSON string using the agent schema
pub fn validate_agent(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let agent_schema = match schema::agent_schema::AgentSchema::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create AgentSchema: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    agent_schema.validate(json).map_err(|e| e.to_string())
}

/// A function to validate an action JSON string using the action schema
pub fn validate_action(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let agent_schema = match schema::action_schema::ActionSchema::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create ActionSchema: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    agent_schema.validate(json).map_err(|e| e.to_string())
}

/// A function to validate an task JSON string using the task schema
pub fn validate_task(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let task_schema = match schema::task_schema::TaskSchema::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create TaskSchema: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    task_schema.validate(json).map_err(|e| e.to_string())
}

/// A function to validate an decision JSON string using the decision schema
pub fn validate_decision(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let decision_schema = match schema::decision_schema::DecisionSchema::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create DecisionSchema: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    decision_schema.validate(json).map_err(|e| e.to_string())
}

pub fn validate_resource(json: &str, version: &str) -> Result<(), String> {
    // TODO , check_signature: bool
    let resource_schema = match schema::resource_schema::ResourceSchema::new(version) {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create DecisionSchema: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    resource_schema.validate(json).map_err(|e| e.to_string())
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
