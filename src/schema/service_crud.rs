use serde_json::{json, Value};

fn create_minimal_service(
    service_description: &str,
    success_description: &str,
    failure_description: &str,
    tools: Option<Vec<Value>>,
    pii_desired: Option<Vec<String>>,
) -> Value {
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

    service
}

fn add_tool_to_service(service: &mut Value, tool: Value) -> Result<(), String> {
    if !service.has_key("tools") {
        service["tools"] = json!([]);
    }
    service["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid service format".to_string())?
        .push(tool);
    Ok(())
}

fn update_tool_in_service(service: &mut Value, old_tool: Value, new_tool: Value) -> Result<(), String> {
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