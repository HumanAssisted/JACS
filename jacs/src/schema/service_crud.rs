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

fn get_array_mut<'a>(service: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, String> {
    service[field]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())
}

fn get_or_init_array_mut<'a>(
    service: &'a mut Value,
    field: &str,
) -> Result<&'a mut Vec<Value>, String> {
    if service.get(field).is_none() {
        service[field] = json!([]);
    }
    get_array_mut(service, field)
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
    get_or_init_array_mut(service, "tools")?.push(tool);
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
    update_value_in_array(
        get_array_mut(service, "tools")?,
        &old_tool,
        new_tool,
        "Tool not found",
    )
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
    remove_value_from_array(get_array_mut(service, "tools")?, &tool, "Tool not found")
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
    get_or_init_array_mut(service, "piiDesired")?.push(json!(pii));
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
    remove_value_from_array(
        get_array_mut(service, "piiDesired")?,
        &json!(pii),
        "Desired PII not found",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn service_tool_crud_round_trip() {
        let mut service = create_minimal_service("desc", "ok", "bad", None, None)
            .expect("minimal service should be created");

        add_tool_to_service(&mut service, json!({"name": "tool-a"})).expect("add tool");
        add_tool_to_service(&mut service, json!({"name": "tool-b"})).expect("add tool");
        assert_eq!(service["tools"].as_array().map(|a| a.len()), Some(2));

        update_tool_in_service(
            &mut service,
            json!({"name": "tool-a"}),
            json!({"name": "tool-a2"}),
        )
        .expect("update tool");
        assert_eq!(service["tools"][0]["name"], "tool-a2");

        remove_tool_from_service(&mut service, json!({"name": "tool-b"})).expect("remove tool");
        assert_eq!(service["tools"].as_array().map(|a| a.len()), Some(1));
    }

    #[test]
    fn pii_desired_crud_round_trip() {
        let mut service = create_minimal_service("desc", "ok", "bad", None, None)
            .expect("minimal service should be created");

        add_pii_desired_to_service(&mut service, "email".to_string()).expect("add pii");
        add_pii_desired_to_service(&mut service, "phone".to_string()).expect("add pii");
        assert_eq!(service["piiDesired"].as_array().map(|a| a.len()), Some(2));

        remove_pii_desired_from_service(&mut service, "email".to_string()).expect("remove pii");
        assert_eq!(service["piiDesired"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(service["piiDesired"][0], "phone");
    }
}
