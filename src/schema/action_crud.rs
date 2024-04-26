use serde_json::{json, Value};

/// Creates a minimal action with required fields and optional tools and units.
///
/// # Arguments
///
/// * `operation` - The operation of the action.
/// * `tools` - An optional vector of tools to be added to the action.
/// * `units` - An optional vector of units to be added to the action.
///
/// # Returns
///
/// A `serde_json::Value` representing the created action.
fn create_minimal_action(operation: &str, tools: Option<Vec<Value>>, units: Option<Vec<Value>>) -> Value {
    json!({
        "operation": operation,
        "tools": tools.unwrap_or_default(),
        "units": units.unwrap_or_default(),
    })
}

/// Adds a tool to an action.
///
/// # Arguments
///
/// * `action` - A mutable reference to the action.
/// * `tool` - The tool to be added.
///
/// # Returns
///
/// * `Ok(())` - If the tool was added successfully.
/// * `Err(String)` - If an error occurred while adding the tool.
fn add_tool_to_action(action: &mut Value, tool: Value) -> Result<(), String> {
    action["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid action format".to_string())?
        .push(tool);
    Ok(())
}

/// Updates a tool in an action.
///
/// # Arguments
///
/// * `action` - A mutable reference to the action.
/// * `old_tool` - The tool to be updated.
/// * `new_tool` - The updated tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool was updated successfully.
/// * `Err(String)` - If an error occurred while updating the tool.
fn update_tool_in_action(action: &mut Value, old_tool: Value, new_tool: Value) -> Result<(), String> {
    let tools = action["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid action format".to_string())?;

    let index = tools
        .iter()
        .position(|t| t == &old_tool)
        .ok_or_else(|| "Tool not found".to_string())?;

    tools[index] = new_tool;
    Ok(())
}

/// Removes a tool from an action.
///
/// # Arguments
///
/// * `action` - A mutable reference to the action.
/// * `tool` - The tool to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the tool was removed successfully.
/// * `Err(String)` - If an error occurred while removing the tool.
fn remove_tool_from_action(action: &mut Value, tool: Value) -> Result<(), String> {
    let tools = action["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid action format".to_string())?;

    let index = tools
        .iter()
        .position(|t| t == &tool)
        .ok_or_else(|| "Tool not found".to_string())?;

    tools.remove(index);
    Ok(())
}

// Similar functions for adding, updating, and removing units.