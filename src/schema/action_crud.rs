use serde_json::{json, Value};

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

// Similar functions for adding, updating, and removing units.
