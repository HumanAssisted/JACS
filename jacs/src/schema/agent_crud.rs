use serde_json::{Value, json};

/// Creates a minimal agent with required fields.
///
/// # Arguments
///
/// * `agent_type` - The type of the agent (e.g., "human", "ai").
/// * `_services` - Ignored legacy argument retained for source compatibility.
/// * `_contacts` - Ignored legacy argument retained for source compatibility.
///
/// # Returns
///
/// A `serde_json::Value` representing the created agent.
///
/// # Errors
///
/// Returns an error if:
/// - `agent_type` is not one of the allowed values.
pub fn create_minimal_agent(
    agent_type: &str,
    _services: Option<Vec<Value>>,
    _contacts: Option<Vec<Value>>,
) -> Result<Value, String> {
    let allowed_agent_types = ["human", "human-org", "hybrid", "ai"];
    if !allowed_agent_types.contains(&agent_type) {
        return Err(format!("Invalid agent type: {}", agent_type));
    }

    let agent = json!({
        "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
        "jacsAgentType": agent_type,
        "jacsType": "agent",
        "jacsLevel": "config"
    });

    Ok(agent)
}
