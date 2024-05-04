use serde_json::{json, Value};

/// Creates a minimal agent with required fields and optional services and contacts.
///
/// # Arguments
///
/// * `agent_type` - The type of the agent (e.g., "human", "ai").
/// * `services` - An optional vector of services to be added to the agent.
/// * `contacts` - An optional vector of contacts to be added to the agent.
///
/// # Returns
///
/// A `serde_json::Value` representing the created agent.
///
/// # Errors
///
/// Returns an error if:
/// - `agent_type` is not one of the allowed values.
/// - `services` is `None` or an empty vector.
pub fn create_minimal_agent(
    agent_type: &str,
    services: Option<Vec<Value>>,
    contacts: Option<Vec<Value>>,
) -> Result<Value, String> {
    let allowed_agent_types = vec!["human", "human-org", "hybrid", "ai"];
    if !allowed_agent_types.contains(&agent_type) {
        return Err(format!("Invalid agent type: {}", agent_type));
    }

    let services = services.ok_or_else(|| "Services are required".to_string())?;
    if services.is_empty() {
        return Err("At least one service is required".to_string());
    }

    let mut agent = json!({
        "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
        "jacsAgentType": agent_type,
        "jacsServices": services,
    });

    if let Some(contacts) = contacts {
        agent["jacsContacts"] = json!(contacts);
    }

    Ok(agent)
}

// Removed unused CRUD functions for services and contacts.
