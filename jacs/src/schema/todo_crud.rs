use serde_json::{Value, json};
use uuid::Uuid;

const ALLOWED_ITEM_TYPES: &[&str] = &["goal", "task"];
const ALLOWED_STATUSES: &[&str] = &["pending", "in-progress", "completed", "abandoned"];
const ALLOWED_PRIORITIES: &[&str] = &["low", "medium", "high", "critical"];

/// Creates a minimal todo list with a name and empty items array.
pub fn create_minimal_todo_list(name: &str) -> Result<Value, String> {
    if name.is_empty() {
        return Err("Todo list name cannot be empty".to_string());
    }

    let doc = json!({
        "$schema": "https://hai.ai/schemas/todo/v1/todo.schema.json",
        "jacsTodoName": name,
        "jacsTodoItems": [],
        "id": Uuid::new_v4().to_string(),
        "jacsType": "todo",
        "jacsLevel": "config",
    });

    Ok(doc)
}

/// Adds a new item to a todo list. Returns the generated itemId.
pub fn add_todo_item(
    list: &mut Value,
    item_type: &str,
    description: &str,
    priority: Option<&str>,
) -> Result<String, String> {
    if !ALLOWED_ITEM_TYPES.contains(&item_type) {
        return Err(format!(
            "Invalid item type: '{}'. Must be one of: {:?}",
            item_type, ALLOWED_ITEM_TYPES
        ));
    }
    if description.is_empty() {
        return Err("Item description cannot be empty".to_string());
    }
    if let Some(p) = priority {
        if !ALLOWED_PRIORITIES.contains(&p) {
            return Err(format!(
                "Invalid priority: '{}'. Must be one of: {:?}",
                p, ALLOWED_PRIORITIES
            ));
        }
    }

    let item_id = Uuid::new_v4().to_string();
    let mut item = json!({
        "itemId": item_id,
        "itemType": item_type,
        "description": description,
        "status": "pending",
    });

    if let Some(p) = priority {
        item["priority"] = json!(p);
    }

    let items = list
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "Invalid todo list: missing jacsTodoItems array".to_string())?;

    items.push(item);
    Ok(item_id)
}

/// Updates the status of a todo item by its itemId.
pub fn update_todo_item_status(
    list: &mut Value,
    item_id: &str,
    new_status: &str,
) -> Result<(), String> {
    if !ALLOWED_STATUSES.contains(&new_status) {
        return Err(format!(
            "Invalid status: '{}'. Must be one of: {:?}",
            new_status, ALLOWED_STATUSES
        ));
    }

    let item = find_item_mut(list, item_id)?;
    item["status"] = json!(new_status);
    Ok(())
}

/// Marks a todo item as completed and sets the completedDate.
pub fn mark_todo_item_complete(list: &mut Value, item_id: &str) -> Result<(), String> {
    let item = find_item_mut(list, item_id)?;
    item["status"] = json!("completed");
    item["completedDate"] = json!(chrono::Utc::now().to_rfc3339());
    Ok(())
}

/// Adds a child item reference to a parent item.
pub fn add_child_to_item(
    list: &mut Value,
    parent_item_id: &str,
    child_item_id: &str,
) -> Result<(), String> {
    let parent = find_item_mut(list, parent_item_id)?;
    if parent.get("childItemIds").is_none() {
        parent["childItemIds"] = json!([]);
    }
    parent["childItemIds"]
        .as_array_mut()
        .ok_or_else(|| "Invalid childItemIds format".to_string())?
        .push(json!(child_item_id));
    Ok(())
}

/// Sets the commitment reference on a todo item.
pub fn set_item_commitment_ref(
    list: &mut Value,
    item_id: &str,
    commitment_id: &str,
) -> Result<(), String> {
    let item = find_item_mut(list, item_id)?;
    item["relatedCommitmentId"] = json!(commitment_id);
    Ok(())
}

/// Sets the conversation thread reference on a todo item.
pub fn set_item_conversation_ref(
    list: &mut Value,
    item_id: &str,
    thread_id: &str,
) -> Result<(), String> {
    let item = find_item_mut(list, item_id)?;
    item["relatedConversationThread"] = json!(thread_id);
    Ok(())
}

/// Adds an archive reference to the todo list.
pub fn add_archive_ref(list: &mut Value, archive_list_id: &str) -> Result<(), String> {
    if list.get("jacsTodoArchiveRefs").is_none() {
        list["jacsTodoArchiveRefs"] = json!([]);
    }
    list["jacsTodoArchiveRefs"]
        .as_array_mut()
        .ok_or_else(|| "Invalid archive refs format".to_string())?
        .push(json!(archive_list_id));
    Ok(())
}

/// Removes completed items from the list and returns them.
pub fn remove_completed_items(list: &mut Value) -> Result<Vec<Value>, String> {
    let items = list
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "Invalid todo list: missing jacsTodoItems array".to_string())?;

    let mut completed = Vec::new();
    let mut remaining = Vec::new();

    for item in items.drain(..) {
        if item.get("status").and_then(|s| s.as_str()) == Some("completed") {
            completed.push(item);
        } else {
            remaining.push(item);
        }
    }

    items.extend(remaining);
    Ok(completed)
}

/// Sets tags on a todo item.
pub fn set_item_tags(list: &mut Value, item_id: &str, tags: Vec<&str>) -> Result<(), String> {
    let item = find_item_mut(list, item_id)?;
    item["tags"] = json!(tags);
    Ok(())
}

/// Sets the assigned agent on a todo item.
pub fn set_item_assigned_agent(
    list: &mut Value,
    item_id: &str,
    agent_id: &str,
) -> Result<(), String> {
    let item = find_item_mut(list, item_id)?;
    item["assignedAgent"] = json!(agent_id);
    Ok(())
}

/// Finds a mutable reference to an item by its itemId.
fn find_item_mut<'a>(list: &'a mut Value, item_id: &str) -> Result<&'a mut Value, String> {
    let items = list
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "Invalid todo list: missing jacsTodoItems array".to_string())?;

    items
        .iter_mut()
        .find(|item| item.get("itemId").and_then(|id| id.as_str()) == Some(item_id))
        .ok_or_else(|| format!("Item with id '{}' not found", item_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_minimal_todo_list() {
        let doc = create_minimal_todo_list("Active Work").unwrap();
        assert_eq!(doc["jacsTodoName"], "Active Work");
        assert_eq!(doc["jacsTodoItems"].as_array().unwrap().len(), 0);
        assert_eq!(doc["jacsType"], "todo");
        assert_eq!(doc["jacsLevel"], "config");
    }

    #[test]
    fn test_create_todo_list_empty_name() {
        let result = create_minimal_todo_list("");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_todo_item() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        let id = add_todo_item(&mut list, "task", "Write tests", Some("high")).unwrap();
        assert!(!id.is_empty());
        let items = list["jacsTodoItems"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["description"], "Write tests");
        assert_eq!(items[0]["itemType"], "task");
        assert_eq!(items[0]["status"], "pending");
        assert_eq!(items[0]["priority"], "high");
    }

    #[test]
    fn test_add_goal_item() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        add_todo_item(&mut list, "goal", "Ship Q1", None).unwrap();
        let items = list["jacsTodoItems"].as_array().unwrap();
        assert_eq!(items[0]["itemType"], "goal");
    }

    #[test]
    fn test_add_item_invalid_type() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        let result = add_todo_item(&mut list, "bug", "Fix it", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_item_status() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        let id = add_todo_item(&mut list, "task", "Do thing", None).unwrap();
        update_todo_item_status(&mut list, &id, "in-progress").unwrap();
        let items = list["jacsTodoItems"].as_array().unwrap();
        assert_eq!(items[0]["status"], "in-progress");
    }

    #[test]
    fn test_mark_complete() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        let id = add_todo_item(&mut list, "task", "Do thing", None).unwrap();
        mark_todo_item_complete(&mut list, &id).unwrap();
        let items = list["jacsTodoItems"].as_array().unwrap();
        assert_eq!(items[0]["status"], "completed");
        assert!(items[0].get("completedDate").is_some());
    }

    #[test]
    fn test_child_items() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        let parent_id = add_todo_item(&mut list, "goal", "Parent", None).unwrap();
        let child_id = add_todo_item(&mut list, "task", "Child", None).unwrap();
        add_child_to_item(&mut list, &parent_id, &child_id).unwrap();
        let items = list["jacsTodoItems"].as_array().unwrap();
        let children = items[0]["childItemIds"].as_array().unwrap();
        assert_eq!(children[0].as_str().unwrap(), child_id);
    }

    #[test]
    fn test_remove_completed_items() {
        let mut list = create_minimal_todo_list("Test").unwrap();
        let id1 = add_todo_item(&mut list, "task", "Done", None).unwrap();
        add_todo_item(&mut list, "task", "Not done", None).unwrap();
        mark_todo_item_complete(&mut list, &id1).unwrap();
        let completed = remove_completed_items(&mut list).unwrap();
        assert_eq!(completed.len(), 1);
        assert_eq!(list["jacsTodoItems"].as_array().unwrap().len(), 1);
    }
}
