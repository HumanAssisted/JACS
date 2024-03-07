pub mod schema;
use log::error;

// A function to validate an agent JSON string using the agent schema
pub fn validate_agent_json(json: &str) -> Result<(), String> {
    let agent_schema = match schema::agent_schema::AgentSchema::new() {
        Ok(schema) => schema,
        Err(e) => {
            let error_message = format!("Failed to create AgentSchema: {}", e);
            error!("{}", error_message);
            return Err(error_message);
        }
    };

    agent_schema.validate(json).map_err(|e| e.to_string())
}
