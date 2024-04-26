use serde_json::{json, Value};
use uuid::Uuid;

/// Creates a minimal task with required fields and optional actions.
///
/// # Arguments
///
/// * `customer` - The customer signature.
/// * `state` - The state of the task (e.g., "open", "closed").
/// * `actions` - An optional vector of actions to be added to the task.
///
/// # Returns
///
/// A `serde_json::Value` representing the created task.
fn create_minimal_task(customer: Value, state: &str, actions: Option<Vec<Value>>) -> Value {
    let mut task = json!({
        "jacsTaskCustomer": customer,
        "jacsTaskState": state,
        "jacsTaskActionsDesired": actions.unwrap_or_default(),
    });

    task["id"] = json!(Uuid::new_v4().to_string());
    task
}

/// Adds an action to a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `action` - The action to be added.
///
/// # Returns
///
/// * `Ok(())` - If the action was added successfully.
/// * `Err(String)` - If an error occurred while adding the action.
fn add_action_to_task(task: &mut Value, action: Value) -> Result<(), String> {
    task["jacsTaskActionsDesired"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .push(action);
    Ok(())
}

/// Updates an action in a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `old_action` - The action to be updated.
/// * `new_action` - The updated action.
///
/// # Returns
///
/// * `Ok(())` - If the action was updated successfully.
/// * `Err(String)` - If an error occurred while updating the action.
fn update_action_in_task(task: &mut Value, old_action: Value, new_action: Value) -> Result<(), String> {
    let actions = task["jacsTaskActionsDesired"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?;

    let index = actions
        .iter()
        .position(|a| a == &old_action)
        .ok_or_else(|| "Action not found".to_string())?;

    actions[index] = new_action;
    Ok(())
}

/// Removes an action from a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `action` - The action to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the action was removed successfully.
/// * `Err(String)` - If an error occurred while removing the action.
fn remove_action_from_task(task: &mut Value, action: Value) -> Result<(), String> {
    let actions = task["jacsTaskActionsDesired"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?;

    let index = actions
        .iter()
        .position(|a| a == &action)
        .ok_or_else(|| "Action not found".to_string())?;

    actions.remove(index);
    Ok(())
}

/// Adds a message to a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `message` - The message to be added.
///
/// # Returns
///
/// * `Ok(())` - If the message was added successfully.
/// * `Err(String)` - If an error occurred while adding the message.
fn add_message_to_task(task: &mut Value, message: Value) -> Result<(), String> {
    task["jacsTaskMessages"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .push(message);
    Ok(())
}