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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_minimal_action_keeps_optional_collections_when_present() {
        let action = create_minimal_action(
            "summarize",
            "Summarize the document",
            Some(vec![json!({"function": {"name": "summarize"}})]),
            Some(vec![json!({"unit": "paragraph"})]),
        );

        assert_eq!(action["description"], json!("Summarize the document"));
        assert_eq!(action["tools"][0]["function"]["name"], json!("summarize"));
        assert_eq!(action["units"][0]["unit"], json!("paragraph"));
    }

    #[test]
    fn action_tool_helpers_add_update_and_remove_tools() {
        let mut action = create_minimal_action("summarize", "Summarize the document", None, None);
        let original_tool = json!({"function": {"name": "summarize"}});
        let replacement_tool = json!({"function": {"name": "classify"}});

        add_tool_to_action(&mut action, original_tool.clone()).unwrap();
        update_tool_in_action(&mut action, original_tool.clone(), replacement_tool.clone())
            .unwrap();
        remove_tool_from_action(&mut action, replacement_tool).unwrap();

        assert_eq!(action["tools"], json!([]));
    }
}
