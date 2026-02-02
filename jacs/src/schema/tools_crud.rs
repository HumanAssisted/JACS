// CRUD operations for future public API - will be exposed in upcoming releases
#![allow(dead_code)]

use serde_json::{Value, json};
use url::Url;

/// Creates a minimal tool with required fields and optional URL.
///
/// # Arguments
///
/// * `name` - The name of the tool.
/// * `description` - A description of what the tool does.
/// * `parameters` - The parameters of the tool.
/// * `url` - An optional URL endpoint of the tool.
///
/// # Returns
///
/// A `serde_json::Value` representing the created tool.
///
/// # Errors
///
/// Returns an error if:
/// - `name`, `description`, or `parameters` is empty.
/// - `url` is provided but is not a valid URL.
fn create_minimal_tool(
    name: &str,
    description: &str,
    parameters: Value,
    url: Option<&str>,
) -> Result<Value, String> {
    if name.is_empty() {
        return Err("Tool name cannot be empty".to_string());
    }
    if description.is_empty() {
        return Err("Tool description cannot be empty".to_string());
    }
    if parameters.is_null() {
        return Err("Tool parameters cannot be empty".to_string());
    }

    let mut tool = json!({
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters,
        },
    });

    if let Some(url) = url {
        let parsed_url = Url::parse(url).map_err(|_| "Invalid URL".to_string())?;
        tool["url"] = json!(parsed_url.to_string());
    }

    let mut wrapped_tool = json!([]);
    wrapped_tool
        .as_array_mut()
        .ok_or_else(|| "Invalid tool format".to_string())?
        .push(tool);

    Ok(wrapped_tool)
}

/// Updates the name of a tool.
///
/// # Arguments
///
/// * `tool` - A mutable reference to the tool.
/// * `new_name` - The new name for the tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool name was updated successfully.
/// * `Err(String)` - If an error occurred while updating the tool name.
fn update_tool_name(tool: &mut Value, new_name: &str) -> Result<(), String> {
    let function = tool["function"]
        .as_object_mut()
        .ok_or_else(|| "Invalid tool format".to_string())?;

    function["name"] = json!(new_name);
    Ok(())
}

/// Updates the description of a tool.
///
/// # Arguments
///
/// * `tool` - A mutable reference to the tool.
/// * `new_description` - The new description for the tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool description was updated successfully.
/// * `Err(String)` - If an error occurred while updating the tool description.
fn update_tool_description(tool: &mut Value, new_description: &str) -> Result<(), String> {
    let function = tool["function"]
        .as_object_mut()
        .ok_or_else(|| "Invalid tool format".to_string())?;

    function["description"] = json!(new_description);
    Ok(())
}

/// Updates the parameters of a tool.
///
/// # Arguments
///
/// * `tool` - A mutable reference to the tool.
/// * `new_parameters` - The new parameters for the tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool parameters were updated successfully.
/// * `Err(String)` - If an error occurred while updating the tool parameters.
fn update_tool_parameters(tool: &mut Value, new_parameters: Value) -> Result<(), String> {
    let function = tool["function"]
        .as_object_mut()
        .ok_or_else(|| "Invalid tool format".to_string())?;

    function["parameters"] = new_parameters;
    Ok(())
}

/// Updates the URL of a tool.
///
/// # Arguments
///
/// * `tool` - A mutable reference to the tool.
/// * `new_url` - The new URL for the tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool URL was updated successfully.
/// * `Err(String)` - If an error occurred while updating the tool URL.
fn update_tool_url(tool: &mut Value, new_url: &str) -> Result<(), String> {
    let parsed_url = Url::parse(new_url).map_err(|_| "Invalid URL".to_string())?;
    tool["url"] = json!(parsed_url.to_string());
    Ok(())
}

/// Removes the URL from a tool.
///
/// # Arguments
///
/// * `tool` - A mutable reference to the tool.
///
/// # Returns
///
/// * `Ok(())` - If the tool URL was removed successfully.
/// * `Err(String)` - If an error occurred while removing the tool URL.
fn remove_tool_url(tool: &mut Value) -> Result<(), String> {
    tool.as_object_mut()
        .ok_or_else(|| "Invalid tool format".to_string())?
        .remove("url");
    Ok(())
}
