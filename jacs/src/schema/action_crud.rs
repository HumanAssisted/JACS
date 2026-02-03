use serde_json::{Value, json};

pub fn create_minimal_action(
    _name: &str,
    description: &str,
    tools: Option<Vec<Value>>,
    units: Option<Vec<Value>>,
) -> Value {
    let mut action = json!({
        "description": description,

    });

    if let Some(tools) = tools {
        action["tools"] = json!(tools);
    }

    if let Some(units) = units {
        action["units"] = json!(units);
    }

    action
}

// CRUD operations for future public API - will be exposed in upcoming releases
#[allow(dead_code)]
fn add_tool_to_action(action: &mut Value, tool: Value) -> Result<(), String> {
    if action.get("tools").is_none() {
        action["tools"] = json!([]);
    }
    action["tools"]
        .as_array_mut()
        .ok_or_else(|| "Invalid action format".to_string())?
        .push(tool);
    Ok(())
}

#[allow(dead_code)]
fn update_tool_in_action(
    action: &mut Value,
    old_tool: Value,
    new_tool: Value,
) -> Result<(), String> {
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

#[allow(dead_code)]
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
