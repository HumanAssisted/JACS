use serde_json::{Value, json};

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
        "jacsType": "agent",
        "jacsServices": services,
        "jacsLevel": "config"
    });

    if let Some(contacts) = contacts {
        agent["jacsContacts"] = json!(contacts);
    }

    Ok(agent)
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

/// Adds a contact to an agent.
///
/// # Arguments
///
/// * `agent` - A mutable reference to the agent.
/// * `contact` - The contact to be added.
///
/// # Returns
///
/// * `Ok(())` - If the contact was added successfully.
/// * `Err(String)` - If an error occurred while adding the contact.
fn add_contact_to_agent(agent: &mut Value, contact: Value) -> Result<(), String> {
    if !agent.get("jacsContacts").is_some() {
        agent["jacsContacts"] = json!([]);
    }
    agent["jacsContacts"]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())?
        .push(contact);
    Ok(())
}

/// Updates a contact in an agent.
///
/// # Arguments
///
/// * `agent` - A mutable reference to the agent.
/// * `old_contact` - The contact to be updated.
/// * `new_contact` - The updated contact.
///
/// # Returns
///
/// * `Ok(())` - If the contact was updated successfully.
/// * `Err(String)` - If an error occurred while updating the contact.
fn update_contact_in_agent(
    agent: &mut Value,
    old_contact: Value,
    new_contact: Value,
) -> Result<(), String> {
    let contacts = agent["jacsContacts"]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())?;

    let index = contacts
        .iter()
        .position(|c| c == &old_contact)
        .ok_or_else(|| "Contact not found".to_string())?;

    contacts[index] = new_contact;
    Ok(())
}

/// Removes a contact from an agent.
///
/// # Arguments
///
/// * `agent` - A mutable reference to the agent.
/// * `contact` - The contact to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the contact was removed successfully.
/// * `Err(String)` - If an error occurred while removing the contact.
fn remove_contact_from_agent(agent: &mut Value, contact: Value) -> Result<(), String> {
    let contacts = agent["jacsContacts"]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())?;

    let index = contacts
        .iter()
        .position(|c| c == &contact)
        .ok_or_else(|| "Contact not found".to_string())?;

    contacts.remove(index);
    Ok(())
}
