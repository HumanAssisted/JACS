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
    let allowed_agent_types = ["human", "human-org", "hybrid", "ai"];
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

fn get_array_mut<'a>(agent: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, String> {
    agent[field]
        .as_array_mut()
        .ok_or_else(|| "Invalid agent format".to_string())
}

fn get_or_init_array_mut<'a>(
    agent: &'a mut Value,
    field: &str,
) -> Result<&'a mut Vec<Value>, String> {
    if agent.get(field).is_none() {
        agent[field] = json!([]);
    }
    get_array_mut(agent, field)
}

fn update_value_in_array(
    values: &mut [Value],
    old_value: &Value,
    new_value: Value,
    not_found_message: &str,
) -> Result<(), String> {
    let index = values
        .iter()
        .position(|v| v == old_value)
        .ok_or_else(|| not_found_message.to_string())?;
    values[index] = new_value;
    Ok(())
}

fn remove_value_from_array(
    values: &mut Vec<Value>,
    target: &Value,
    not_found_message: &str,
) -> Result<(), String> {
    let index = values
        .iter()
        .position(|v| v == target)
        .ok_or_else(|| not_found_message.to_string())?;
    values.remove(index);
    Ok(())
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
// CRUD operations for future public API - will be exposed in upcoming releases
#[allow(dead_code)]
fn add_service_to_agent(agent: &mut Value, service: Value) -> Result<(), String> {
    get_array_mut(agent, "jacsServices")?.push(service);
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
#[allow(dead_code)]
fn update_service_in_agent(
    agent: &mut Value,
    old_service: Value,
    new_service: Value,
) -> Result<(), String> {
    update_value_in_array(
        get_array_mut(agent, "jacsServices")?,
        &old_service,
        new_service,
        "Service not found",
    )
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
#[allow(dead_code)]
fn remove_service_from_agent(agent: &mut Value, service: Value) -> Result<(), String> {
    remove_value_from_array(
        get_array_mut(agent, "jacsServices")?,
        &service,
        "Service not found",
    )
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
#[allow(dead_code)]
fn add_contact_to_agent(agent: &mut Value, contact: Value) -> Result<(), String> {
    get_or_init_array_mut(agent, "jacsContacts")?.push(contact);
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
#[allow(dead_code)]
fn update_contact_in_agent(
    agent: &mut Value,
    old_contact: Value,
    new_contact: Value,
) -> Result<(), String> {
    update_value_in_array(
        get_array_mut(agent, "jacsContacts")?,
        &old_contact,
        new_contact,
        "Contact not found",
    )
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
#[allow(dead_code)]
fn remove_contact_from_agent(agent: &mut Value, contact: Value) -> Result<(), String> {
    remove_value_from_array(
        get_array_mut(agent, "jacsContacts")?,
        &contact,
        "Contact not found",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_update_remove_service_works() {
        let mut agent = json!({
            "jacsServices": [
                {"name": "svc-a"},
                {"name": "svc-b"}
            ]
        });

        add_service_to_agent(&mut agent, json!({"name": "svc-c"})).expect("add");
        assert_eq!(agent["jacsServices"].as_array().map(|a| a.len()), Some(3));

        update_service_in_agent(
            &mut agent,
            json!({"name": "svc-a"}),
            json!({"name": "svc-a2"}),
        )
        .expect("update");
        assert_eq!(agent["jacsServices"][0]["name"], "svc-a2");

        remove_service_from_agent(&mut agent, json!({"name": "svc-b"})).expect("remove");
        assert_eq!(agent["jacsServices"].as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn contact_operations_initialize_and_edit_array() {
        let mut agent = json!({
            "jacsServices": [{"name": "svc"}]
        });

        add_contact_to_agent(&mut agent, json!({"email": "one@example.com"})).expect("add 1");
        add_contact_to_agent(&mut agent, json!({"email": "two@example.com"})).expect("add 2");
        assert_eq!(agent["jacsContacts"].as_array().map(|a| a.len()), Some(2));

        update_contact_in_agent(
            &mut agent,
            json!({"email": "one@example.com"}),
            json!({"email": "one+updated@example.com"}),
        )
        .expect("update");
        assert_eq!(
            agent["jacsContacts"][0]["email"],
            json!("one+updated@example.com")
        );

        remove_contact_from_agent(&mut agent, json!({"email": "two@example.com"})).expect("remove");
        assert_eq!(agent["jacsContacts"].as_array().map(|a| a.len()), Some(1));
    }
}
