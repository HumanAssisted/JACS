// CRUD operations for future public API - will be exposed in upcoming releases
#![allow(dead_code)]

use serde_json::{Value, json};

/// Creates a minimal service with required fields and optional tools and PII desired.
///
/// # Arguments
///
/// * `service_description` - The description of the service.
/// * `success_description` - The description of successful delivery of the service.
/// * `failure_description` - The description of failure of delivery of the service.
/// * `tools` - An optional vector of tools associated with the service.
/// * `pii_desired` - An optional vector of desired personally identifiable information (PII).
///
/// # Returns
///
/// A `serde_json::Value` representing the created service.
///
/// # Errors
///
/// Returns an error if:
/// - `service_description`, `success_description`, or `failure_description` is empty.
///
pub fn create_minimal_service(
    service_description: &str,
    success_description: &str,
    failure_description: &str,
    tools: Option<Vec<Value>>,
    pii_desired: Option<Vec<String>>,
) -> Result<Value, String> {
    if service_description.is_empty() {
        return Err("Service description cannot be empty".to_string());
    }
    if success_description.is_empty() {
        return Err("Success description cannot be empty".to_string());
    }
    if failure_description.is_empty() {
        return Err("Failure description cannot be empty".to_string());
    }

    let mut service = json!({
        "serviceDescription": service_description,
        "successDescription": success_description,
        "failureDescription": failure_description,
    });

    if let Some(tools) = tools {
        service["tools"] = json!(tools);
    }

    if let Some(pii_desired) = pii_desired {
        service["piiDesired"] = json!(pii_desired);
    }

    Ok(service)
}

/// Adds a tool to a service.
///
/// # Arguments
///
/// * `service` - A mutable reference to the service.
/// * `tool` - The tool to be added.
///
/// # Returns
///
/// * `Ok(())` - If the tool was added successfully.
/// * `Err(String)` - If an error occurred while adding the tool.
fn add_tool_to_service(service: &mut Value, tool: Value) -> Result<(), String> {
    if service.get("tools").is_none() {
        service["tools"] = json!([]);
    }
    service["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())?
        .push(tool);
    Ok(())
}

/// Updates a tool in a service.
///
/// # Arguments
///
/// * `service` - A mutable reference to the service.
/// * `old_tool` - The tool to be updated.
/// * `new_tool` - The updated tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool was updated successfully.
/// * `Err(String)` - If an error occurred while updating the tool.
fn update_tool_in_service(
    service: &mut Value,
    old_tool: Value,
    new_tool: Value,
) -> Result<(), String> {
    let tools = service["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())?;

    let index = tools
        .iter()
        .position(|t| t == &old_tool)
        .ok_or_else(|| "Tool not found".to_string())?;

    tools[index] = new_tool;
    Ok(())
}

/// Removes a tool from a service.
///
/// # Arguments
///
/// * `service` - A mutable reference to the service.
/// * `tool` - The tool to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the tool was removed successfully.
/// * `Err(String)` - If an error occurred while removing the tool.
fn remove_tool_from_service(service: &mut Value, tool: Value) -> Result<(), String> {
    let tools = service["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())?;

    let index = tools
        .iter()
        .position(|t| t == &tool)
        .ok_or_else(|| "Tool not found".to_string())?;

    tools.remove(index);
    Ok(())
}

/// Adds desired PII to a service.
///
/// # Arguments
///
/// * `service` - A mutable reference to the service.
/// * `pii` - The desired PII to be added.
///
/// # Returns
///
/// * `Ok(())` - If the desired PII was added successfully.
/// * `Err(String)` - If an error occurred while adding the desired PII.
fn add_pii_desired_to_service(service: &mut Value, pii: String) -> Result<(), String> {
    if service.get("piiDesired").is_none() {
        service["piiDesired"] = json!([]);
    }
    service["piiDesired"]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())?
        .push(json!(pii));
    Ok(())
}

/// Removes desired PII from a service.
///
/// # Arguments
///
/// * `service` - A mutable reference to the service.
/// * `pii` - The desired PII to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the desired PII was removed successfully.
/// * `Err(String)` - If an error occurred while removing the desired PII.
fn remove_pii_desired_from_service(service: &mut Value, pii: String) -> Result<(), String> {
    let pii_desired = service["piiDesired"]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())?;

    let index = pii_desired
        .iter()
        .position(|p| p == &pii)
        .ok_or_else(|| "Desired PII not found".to_string())?;

    pii_desired.remove(index);
    Ok(())
}
