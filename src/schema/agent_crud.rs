use serde_json::{json, Value};
use uuid::Uuid;

/// Creates a minimal agent with required fields and optional services.
///
/// # Arguments
///
/// * `agent_type` - The type of the agent (e.g., "human", "ai").
/// * `services` - An optional vector of services to be added to the agent.
///
/// # Returns
///
/// A `serde_json::Value` representing the created agent.
fn create_minimal_agent(agent_type: &str, services: Option<Vec<Value>>) -> Value {
    let mut agent = json!({
        "jacsAgentType": agent_type,
        "jacsServices": services.unwrap_or_default(),
    });

    agent
}

/// Adds a service to an agent.
///
/// # Arguments
///
/// * `agent` - A mutable reference to the agent.
/// * `service` - The service to be added.
///
/// # Returns
///
/// * `Ok(())` - If the service was added successfully.
/// * `Err(String)` - If an error occurred while adding the service.
fn add_service_to_agent(agent: &mut Value, service: Value) -> Result<(), String> {
    agent["jacsServices"]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())?
        .push(service);
    Ok(())
}

/// Updates a service in an agent.
///
/// # Arguments
///
/// * `agent` - A mutable reference to the agent.
/// * `old_service` - The service to be updated.
/// * `new_service` - The updated service.
///
/// # Returns
///
/// * `Ok(())` - If the service was updated successfully.
/// * `Err(String)` - If an error occurred while updating the service.
fn update_service_in_agent(
    agent: &mut Value,
    old_service: Value,
    new_service: Value,
) -> Result<(), String> {
    let services = agent["jacsServices"]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())?;

    let index = services
        .iter()
        .position(|s| s == &old_service)
        .ok_or_else(|| "Service not found".to_string())?;

    services[index] = new_service;
    Ok(())
}

/// Removes a service from an agent.
///
/// # Arguments
///
/// * `agent` - A mutable reference to the agent.
/// * `service` - The service to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the service was removed successfully.
/// * `Err(String)` - If an error occurred while removing the service.
fn remove_service_from_agent(agent: &mut Value, service: Value) -> Result<(), String> {
    let services = agent["jacsServices"]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())?;

    let index = services
        .iter()
        .position(|s| s == &service)
        .ok_or_else(|| "Service not found".to_string())?;

    services.remove(index);
    Ok(())
}

// Similar functions for adding, updating, and removing contacts and tools.
