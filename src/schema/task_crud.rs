use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

/// Creates a minimal task with required fields and optional actions and messages.
///
/// # Arguments
///
/// * `customer` - The customer signature.
/// * `state` - The state of the task (e.g., "open", "closed").
/// * `actions` - An optional vector of actions to be added to the task.
/// * `messages` - An optional vector of messages to be added to the task.
/// * `start_date` - An optional start date for the task.
/// * `complete_date` - An optional complete date for the task.
///
/// # Returns
///
/// A `serde_json::Value` representing the created task.
///
/// # Errors
///
/// Returns an error if:
/// - `customer` is empty.
/// - `state` is not one of the allowed values.
pub fn create_minimal_task(
    actions: Option<Vec<Value>>,
    messages: Option<Vec<Value>>,
    start_date: Option<DateTime<Utc>>,
    complete_date: Option<DateTime<Utc>>,
) -> Result<Value, String> {
    let mut task = json!({
        "$schema": "https://hai.ai/schemas/task/v1/task.schema.json",
        "jacsTaskState": "creating",
    });

    if let Some(actions) = actions {
        task["jacsTaskActionsDesired"] = json!(actions);
    }

    if let Some(messages) = messages {
        task["jacsTaskMessages"] = json!(messages);
    }

    if let Some(start_date) = start_date {
        task["jacsTaskStartDate"] = json!(start_date.to_rfc3339());
    }

    if let Some(complete_date) = complete_date {
        task["jacsTaskCompleteDate"] = json!(complete_date.to_rfc3339());
    }

    task["id"] = json!(Uuid::new_v4().to_string());
    task["jacsType"] = json!("task");
    Ok(task)
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
pub fn add_action_to_task(task: &mut Value, action: Value) -> Result<(), String> {
    if !task.get("jacsTaskActionsDesired").is_some() {
        task["jacsTaskActionsDesired"] = json!([]);
    }
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
pub fn update_action_in_task(
    task: &mut Value,
    old_action: Value,
    new_action: Value,
) -> Result<(), String> {
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
pub fn remove_action_from_task(task: &mut Value, action: Value) -> Result<(), String> {
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

/// Updates the state of a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `new_state` - The new state for the task.
///
/// # Returns
///
/// * `Ok(())` - If the task state was updated successfully.
/// * `Err(String)` - If an error occurred while updating the task state.
pub fn update_task_state(task: &mut Value, new_state: &str) -> Result<(), String> {
    let allowed_states = vec!["open", "editlock", "closed"];
    if !allowed_states.contains(&new_state) {
        return Err(format!("Invalid task state: {}", new_state));
    }
    task["jacsTaskState"] = json!(new_state);
    Ok(())
}

/// Updates the start date of a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `new_start_date` - The new start date for the task.
///
/// # Returns
///
/// * `Ok(())` - If the task start date was updated successfully.
/// * `Err(String)` - If an error occurred while updating the task start date.
pub fn update_task_start_date(
    task: &mut Value,
    new_start_date: DateTime<Utc>,
) -> Result<(), String> {
    task["jacsTaskStartDate"] = json!(new_start_date.to_rfc3339());
    Ok(())
}

/// Removes the start date from a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
///
/// # Returns
///
/// * `Ok(())` - If the task start date was removed successfully.
/// * `Err(String)` - If an error occurred while removing the task start date.
pub fn remove_task_start_date(task: &mut Value) -> Result<(), String> {
    task.as_object_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .remove("jacsTaskStartDate");
    Ok(())
}

/// Updates the complete date of a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `new_complete_date` - The new complete date for the task.
///
/// # Returns
///
/// * `Ok(())` - If the task complete date was updated successfully.
/// * `Err(String)` - If an error occurred while updating the task complete date.
pub fn update_task_complete_date(
    task: &mut Value,
    new_complete_date: DateTime<Utc>,
) -> Result<(), String> {
    task["jacsTaskCompleteDate"] = json!(new_complete_date.to_rfc3339());
    Ok(())
}

/// Removes the complete date from a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
///
/// # Returns
///
/// * `Ok(())` - If the task complete date was removed successfully.
/// * `Err(String)` - If an error occurred while removing the task complete date.
pub fn remove_task_complete_date(task: &mut Value) -> Result<(), String> {
    task.as_object_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .remove("jacsTaskCompleteDate");
    Ok(())
}

/// Adds a subtask to a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `subtask_id` - The ID of the subtask to be added.
///
/// # Returns
///
/// * `Ok(())` - If the subtask was added successfully.
/// * `Err(String)` - If an error occurred while adding the subtask.
pub fn add_subtask_to_task(task: &mut Value, subtask_id: &str) -> Result<(), String> {
    if !task.get("jacsTaskSubTaskOf").is_some() {
        task["jacsTaskSubTaskOf"] = json!([]);
    }
    task["jacsTaskSubTaskOf"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .push(json!(subtask_id));
    Ok(())
}

/// Removes a subtask from a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `subtask_id` - The ID of the subtask to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the subtask was removed successfully.
/// * `Err(String)` - If an error occurred while removing the subtask.
pub fn remove_subtask_from_task(task: &mut Value, subtask_id: &str) -> Result<(), String> {
    let subtasks = task["jacsTaskSubTaskOf"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?;

    let index = subtasks
        .iter()
        .position(|s| s == subtask_id)
        .ok_or_else(|| "Subtask not found".to_string())?;

    subtasks.remove(index);
    Ok(())
}

/// Adds a copy task to a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `copy_task_id` - The ID of the copy task to be added.
///
/// # Returns
///
/// * `Ok(())` - If the copy task was added successfully.
/// * `Err(String)` - If an error occurred while adding the copy task.
pub fn add_copy_task_to_task(task: &mut Value, copy_task_id: &str) -> Result<(), String> {
    if !task.get("jacsTaskCopyOf").is_some() {
        task["jacsTaskCopyOf"] = json!([]);
    }
    task["jacsTaskCopyOf"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .push(json!(copy_task_id));
    Ok(())
}

/// Removes a copy task from a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `copy_task_id` - The ID of the copy task to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the copy task was removed successfully.
/// * `Err(String)` - If an error occurred while removing the copy task.
pub fn remove_copy_task_from_task(task: &mut Value, copy_task_id: &str) -> Result<(), String> {
    let copy_tasks = task["jacsTaskCopyOf"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?;

    let index = copy_tasks
        .iter()
        .position(|c| c == copy_task_id)
        .ok_or_else(|| "Copy task not found".to_string())?;

    copy_tasks.remove(index);
    Ok(())
}

/// Adds a merged task to a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `merged_task_id` - The ID of the merged task to be added.
///
/// # Returns
///
/// * `Ok(())` - If the merged task was added successfully.
/// * `Err(String)` - If an error occurred while adding the merged task.
pub fn add_merged_task_to_task(task: &mut Value, merged_task_id: &str) -> Result<(), String> {
    if !task.get("jacsTaskMergedTasks").is_some() {
        task["jacsTaskMergedTasks"] = json!([]);
    }
    task["jacsTaskMergedTasks"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?
        .push(json!(merged_task_id));
    Ok(())
}

/// Removes a merged task from a task.
///
/// # Arguments
///
/// * `task` - A mutable reference to the task.
/// * `merged_task_id` - The ID of the merged task to be removed.
///
/// # Returns
///
/// * `Ok(())` - If the merged task was removed successfully.
/// * `Err(String)` - If an error occurred while removing the merged task.
pub fn remove_merged_task_from_task(task: &mut Value, merged_task_id: &str) -> Result<(), String> {
    let merged_tasks = task["jacsTaskMergedTasks"]
        .as_array_mut()
        .ok_or_else(|| "Invalid task format".to_string())?;

    let index = merged_tasks
        .iter()
        .position(|m| m == merged_task_id)
        .ok_or_else(|| "Merged task not found".to_string())?;

    merged_tasks.remove(index);
    Ok(())
}
