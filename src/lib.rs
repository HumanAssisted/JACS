pub mod schema;

// A function to validate an agent JSON string using the agent schema
pub fn validate_agent_json(json: &str) -> Result<(), String> {
    let agent_schema = schema::agent_schema::AgentSchema::new()
        .map_err(|e| e.to_string())?;

    agent_schema.validate(json).map_err(|e| e.to_string())
}