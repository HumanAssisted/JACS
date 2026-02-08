use jacs::agent::document::DocumentTraits;
use jacs::schema::todo_crud::{
    add_archive_ref, add_child_to_item, add_todo_item, create_minimal_todo_list,
    mark_todo_item_complete, remove_completed_items, set_item_commitment_ref,
    set_item_conversation_ref, set_item_tags, update_todo_item_status,
};
use serde_json::json;

mod utils;
use utils::load_test_agent_one;

// =============================================================================
// Phase 1C: Schema / CRUD Tests (Steps 51-63)
// =============================================================================

/// Step 51: Create a minimal todo list with an empty items array.
/// Verify jacsType="todo" and jacsLevel="config".
#[test]
fn test_create_minimal_todo_list() {
    let doc =
        create_minimal_todo_list("My Active Work").expect("Should create a minimal todo list");

    assert_eq!(doc["jacsTodoName"], "My Active Work");
    assert_eq!(
        doc["jacsTodoItems"]
            .as_array()
            .expect("jacsTodoItems should be an array")
            .len(),
        0,
        "New todo list should have no items"
    );
    assert_eq!(doc["jacsType"], "todo");
    assert_eq!(doc["jacsLevel"], "config");
    assert_eq!(
        doc["$schema"],
        "https://hai.ai/schemas/todo/v1/todo.schema.json"
    );
}

/// Step 52: Add a goal-type item to the todo list.
#[test]
fn test_todo_list_with_goal_item() {
    let mut list = create_minimal_todo_list("Goals List").expect("Should create todo list");

    let goal_id = add_todo_item(&mut list, "goal", "Ship Q1 release", Some("high"))
        .expect("Should add goal item");

    assert!(!goal_id.is_empty(), "Goal ID should be a non-empty UUID");

    let items = list["jacsTodoItems"]
        .as_array()
        .expect("jacsTodoItems should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["itemType"], "goal");
    assert_eq!(items[0]["description"], "Ship Q1 release");
    assert_eq!(items[0]["status"], "pending");
    assert_eq!(items[0]["priority"], "high");
    assert_eq!(items[0]["itemId"].as_str().unwrap(), goal_id);
}

/// Step 53: Add a task-type item to the todo list.
#[test]
fn test_todo_list_with_task_item() {
    let mut list = create_minimal_todo_list("Task List").expect("Should create todo list");

    let task_id = add_todo_item(&mut list, "task", "Write integration tests", Some("medium"))
        .expect("Should add task item");

    let items = list["jacsTodoItems"]
        .as_array()
        .expect("jacsTodoItems should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["itemType"], "task");
    assert_eq!(items[0]["description"], "Write integration tests");
    assert_eq!(items[0]["status"], "pending");
    assert_eq!(items[0]["priority"], "medium");
    assert_eq!(items[0]["itemId"].as_str().unwrap(), task_id);
}

/// Step 54: Goal with childItemIds referencing task items.
#[test]
fn test_todo_goal_with_child_tasks() {
    let mut list = create_minimal_todo_list("Goal with Children").expect("Should create todo list");

    let goal_id =
        add_todo_item(&mut list, "goal", "Complete Q1 milestones", None).expect("Should add goal");
    let task_id_1 =
        add_todo_item(&mut list, "task", "Review designs", None).expect("Should add task 1");
    let task_id_2 =
        add_todo_item(&mut list, "task", "Implement feature", None).expect("Should add task 2");

    add_child_to_item(&mut list, &goal_id, &task_id_1).expect("Should add child 1 to goal");
    add_child_to_item(&mut list, &goal_id, &task_id_2).expect("Should add child 2 to goal");

    let items = list["jacsTodoItems"]
        .as_array()
        .expect("jacsTodoItems should be an array");
    assert_eq!(items.len(), 3, "Should have 1 goal + 2 tasks");

    // The goal (first item) should have childItemIds
    let children = items[0]["childItemIds"]
        .as_array()
        .expect("Goal should have childItemIds array");
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].as_str().unwrap(), task_id_1);
    assert_eq!(children[1].as_str().unwrap(), task_id_2);
}

/// Step 55: Verify all valid statuses: pending, in-progress, completed, abandoned.
#[test]
fn test_todo_item_all_valid_statuses() {
    let valid_statuses = ["pending", "in-progress", "completed", "abandoned"];

    for status in &valid_statuses {
        let mut list = create_minimal_todo_list(&format!("Status test: {}", status))
            .expect("Should create todo list");

        let item_id = add_todo_item(&mut list, "task", &format!("Test {}", status), None)
            .expect("Should add item");

        update_todo_item_status(&mut list, &item_id, status)
            .unwrap_or_else(|e| panic!("Failed for status '{}': {}", status, e));

        let items = list["jacsTodoItems"].as_array().unwrap();
        assert_eq!(
            items[0]["status"], *status,
            "Status should be set to '{}'",
            status
        );
    }
}

/// Step 56: Reject an invalid status value.
#[test]
fn test_todo_item_invalid_status() {
    let mut list =
        create_minimal_todo_list("Invalid status test").expect("Should create todo list");

    let item_id = add_todo_item(&mut list, "task", "Will fail", None).expect("Should add item");

    let result = update_todo_item_status(&mut list, &item_id, "bogus");
    assert!(result.is_err(), "Invalid status 'bogus' should be rejected");

    let result2 = update_todo_item_status(&mut list, &item_id, "done");
    assert!(result2.is_err(), "Invalid status 'done' should be rejected");

    let result3 = update_todo_item_status(&mut list, &item_id, "");
    assert!(result3.is_err(), "Empty status should be rejected");

    // Original status should be unchanged
    let items = list["jacsTodoItems"].as_array().unwrap();
    assert_eq!(
        items[0]["status"], "pending",
        "Status should remain 'pending' after failed updates"
    );
}

/// Step 57: Verify all valid priorities: low, medium, high, critical.
#[test]
fn test_todo_item_all_priorities() {
    let valid_priorities = ["low", "medium", "high", "critical"];

    for priority in &valid_priorities {
        let mut list = create_minimal_todo_list(&format!("Priority test: {}", priority))
            .expect("Should create todo list");

        let item_id = add_todo_item(
            &mut list,
            "task",
            &format!("Priority {} task", priority),
            Some(priority),
        )
        .unwrap_or_else(|e| panic!("Failed for priority '{}': {}", priority, e));

        let items = list["jacsTodoItems"].as_array().unwrap();
        assert_eq!(
            items[0]["priority"], *priority,
            "Priority should be '{}'",
            priority
        );
        assert!(!item_id.is_empty());
    }
}

/// Step 58: Item references a commitment via relatedCommitmentId.
#[test]
fn test_todo_item_references_commitment() {
    let mut list =
        create_minimal_todo_list("Commitment ref test").expect("Should create todo list");

    let item_id =
        add_todo_item(&mut list, "task", "Linked to commitment", None).expect("Should add item");

    let commitment_uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    set_item_commitment_ref(&mut list, &item_id, commitment_uuid)
        .expect("Should set commitment reference");

    let items = list["jacsTodoItems"].as_array().unwrap();
    assert_eq!(
        items[0]["relatedCommitmentId"], commitment_uuid,
        "relatedCommitmentId should be set"
    );
}

/// Step 59: Item with tags array.
#[test]
fn test_todo_item_with_tags() {
    let mut list = create_minimal_todo_list("Tags test").expect("Should create todo list");

    let item_id = add_todo_item(&mut list, "task", "Tagged item", None).expect("Should add item");

    set_item_tags(&mut list, &item_id, vec!["urgent", "backend", "Q1"]).expect("Should set tags");

    let items = list["jacsTodoItems"].as_array().unwrap();
    let tags = items[0]["tags"]
        .as_array()
        .expect("tags should be an array");
    assert_eq!(tags.len(), 3);
    assert_eq!(tags[0], "urgent");
    assert_eq!(tags[1], "backend");
    assert_eq!(tags[2], "Q1");
}

/// Step 60: Item references a conversation thread.
#[test]
fn test_todo_item_references_conversation() {
    let mut list =
        create_minimal_todo_list("Conversation ref test").expect("Should create todo list");

    let item_id =
        add_todo_item(&mut list, "task", "From conversation", None).expect("Should add item");

    let thread_uuid = "c0ffee00-dead-beef-cafe-123456789abc";
    set_item_conversation_ref(&mut list, &item_id, thread_uuid)
        .expect("Should set conversation ref");

    let items = list["jacsTodoItems"].as_array().unwrap();
    assert_eq!(
        items[0]["relatedConversationThread"], thread_uuid,
        "relatedConversationThread should be set"
    );
}

/// Step 61: Archive references on a todo list.
#[test]
fn test_todo_list_archive_refs() {
    let mut list = create_minimal_todo_list("Archive ref test").expect("Should create todo list");

    let archive_uuid_1 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let archive_uuid_2 = "11111111-2222-3333-4444-555555555555";

    add_archive_ref(&mut list, archive_uuid_1).expect("Should add first archive ref");
    add_archive_ref(&mut list, archive_uuid_2).expect("Should add second archive ref");

    let refs = list["jacsTodoArchiveRefs"]
        .as_array()
        .expect("jacsTodoArchiveRefs should be an array");
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0], archive_uuid_1);
    assert_eq!(refs[1], archive_uuid_2);
}

/// Step 62: Reject invalid item type.
#[test]
fn test_todo_item_invalid_type() {
    let mut list = create_minimal_todo_list("Invalid type test").expect("Should create todo list");

    let result = add_todo_item(&mut list, "bug", "Not a valid type", None);
    assert!(result.is_err(), "Item type 'bug' should be rejected");

    let result2 = add_todo_item(&mut list, "epic", "Also invalid", None);
    assert!(result2.is_err(), "Item type 'epic' should be rejected");

    let result3 = add_todo_item(&mut list, "", "Empty type", None);
    assert!(result3.is_err(), "Empty item type should be rejected");

    // No items should have been added
    let items = list["jacsTodoItems"].as_array().unwrap();
    assert_eq!(items.len(), 0, "No items should exist after rejected adds");
}

/// Step 63: Reject empty description.
#[test]
fn test_todo_item_empty_description() {
    let mut list = create_minimal_todo_list("Empty desc test").expect("Should create todo list");

    let result = add_todo_item(&mut list, "task", "", None);
    assert!(result.is_err(), "Empty description should be rejected");

    let items = list["jacsTodoItems"].as_array().unwrap();
    assert_eq!(items.len(), 0, "No items should exist after rejected add");
}

// =============================================================================
// Phase 1C: Signing and Integration Tests (Steps 64-71)
// =============================================================================

/// Step 64: Create a todo list, add items, sign via agent, and verify signature.
#[test]
fn test_todo_list_signing_and_verification() {
    let mut agent = load_test_agent_one();

    let mut list = create_minimal_todo_list("Signing test list").expect("Should create todo list");

    add_todo_item(&mut list, "goal", "Ship the feature", Some("high")).expect("Should add goal");
    add_todo_item(&mut list, "task", "Write tests", Some("medium")).expect("Should add task");

    // Sign through agent pipeline
    let loaded = agent
        .create_document_and_load(&list.to_string(), None, None)
        .expect("Should load and sign todo list");

    let doc_key = loaded.getkey();
    let value = loaded.getvalue();

    // Must have a signature
    assert!(
        value.get("jacsSignature").is_some(),
        "Signed todo list must have jacsSignature"
    );
    assert!(
        value["jacsSignature"].is_object(),
        "jacsSignature must be a JSON object"
    );

    // Must have jacsId and jacsVersion
    assert!(
        value.get("jacsId").is_some() && value["jacsId"].as_str().is_some(),
        "Signed todo list must have jacsId"
    );
    assert!(
        value.get("jacsVersion").is_some() && value["jacsVersion"].as_str().is_some(),
        "Signed todo list must have jacsVersion"
    );

    // Items should be preserved
    let items = value["jacsTodoItems"]
        .as_array()
        .expect("jacsTodoItems should be an array after signing");
    assert_eq!(
        items.len(),
        2,
        "Both items should be preserved after signing"
    );
    assert_eq!(items[0]["itemType"], "goal");
    assert_eq!(items[1]["itemType"], "task");

    // Verify the signature
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_result.is_ok(),
        "Signature verification should succeed: {:?}",
        verify_result.err()
    );
}

/// Step 65: Modify item status, re-sign via update_document, and verify.
#[test]
fn test_todo_list_update_and_resign() {
    let mut agent = load_test_agent_one();

    let mut list = create_minimal_todo_list("Update test list").expect("Should create todo list");

    let task_id =
        add_todo_item(&mut list, "task", "Task to update", None).expect("Should add task");

    // Version 1: sign
    let v1 = agent
        .create_document_and_load(&list.to_string(), None, None)
        .expect("Should load todo list v1");

    let v1_key = v1.getkey();
    let v1_value = v1.getvalue().clone();
    let v1_version = v1_value["jacsVersion"]
        .as_str()
        .expect("v1 should have jacsVersion")
        .to_string();

    // Modify the item status in the signed document
    let mut v2_input = v1_value.clone();
    // Find the item by iterating and update status
    if let Some(items) = v2_input
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
    {
        for item in items.iter_mut() {
            if item.get("itemId").and_then(|id| id.as_str()) == Some(&task_id) {
                item["status"] = json!("in-progress");
            }
        }
    }

    // Version 2: update and re-sign
    let v2 = agent
        .update_document(&v1_key, &v2_input.to_string(), None, None)
        .expect("Should update todo list");

    let v2_key = v2.getkey();
    let v2_value = v2.getvalue();
    let v2_version = v2_value["jacsVersion"]
        .as_str()
        .expect("v2 should have jacsVersion");

    // Version must have changed
    assert_ne!(
        v1_version, v2_version,
        "Updated todo list must have a different jacsVersion"
    );

    // Previous version must point to v1
    let prev_version = v2_value["jacsPreviousVersion"]
        .as_str()
        .expect("v2 should have jacsPreviousVersion");
    assert_eq!(
        prev_version, v1_version,
        "jacsPreviousVersion must equal v1's jacsVersion"
    );

    // Updated status should be preserved
    let items = v2_value["jacsTodoItems"].as_array().unwrap();
    assert_eq!(items[0]["status"], "in-progress");

    // Verify the new signature
    let verify_result = agent.verify_document_signature(&v2_key, None, None, None, None);
    assert!(
        verify_result.is_ok(),
        "Re-signed todo list should verify: {:?}",
        verify_result.err()
    );
}

/// Step 66: Version chain: add item -> mark complete -> verify chain across 3 versions.
#[test]
fn test_todo_list_versioning_on_update() {
    let mut agent = load_test_agent_one();

    // Version 1: empty list
    let list = create_minimal_todo_list("Version chain test").expect("Should create todo list");

    let v1 = agent
        .create_document_and_load(&list.to_string(), None, None)
        .expect("Should load v1");

    let v1_key = v1.getkey();
    let v1_value = v1.getvalue().clone();
    let v1_version = v1_value["jacsVersion"]
        .as_str()
        .expect("v1 should have jacsVersion")
        .to_string();

    // Version 2: add an item
    let mut v2_input = v1_value.clone();
    let task_id = uuid::Uuid::new_v4().to_string();
    let new_item = json!({
        "itemId": task_id,
        "itemType": "task",
        "description": "A new task",
        "status": "pending"
    });
    v2_input["jacsTodoItems"]
        .as_array_mut()
        .unwrap()
        .push(new_item);

    let v2 = agent
        .update_document(&v1_key, &v2_input.to_string(), None, None)
        .expect("Should create v2");

    let v2_key = v2.getkey();
    let v2_value = v2.getvalue().clone();
    let v2_version = v2_value["jacsVersion"]
        .as_str()
        .expect("v2 should have jacsVersion")
        .to_string();

    // Verify v2 previous points to v1
    assert_eq!(
        v2_value["jacsPreviousVersion"].as_str().unwrap(),
        v1_version,
        "v2's jacsPreviousVersion must equal v1's jacsVersion"
    );

    // Version 3: mark item complete
    let mut v3_input = v2_value.clone();
    if let Some(items) = v3_input
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
    {
        for item in items.iter_mut() {
            if item.get("itemId").and_then(|id| id.as_str()) == Some(&task_id) {
                item["status"] = json!("completed");
                item["completedDate"] = json!("2026-02-05T12:00:00Z");
            }
        }
    }

    let v3 = agent
        .update_document(&v2_key, &v3_input.to_string(), None, None)
        .expect("Should create v3");

    let v3_key = v3.getkey();
    let v3_value = v3.getvalue();
    let v3_version = v3_value["jacsVersion"]
        .as_str()
        .expect("v3 should have jacsVersion")
        .to_string();

    // Verify v3 previous points to v2
    assert_eq!(
        v3_value["jacsPreviousVersion"].as_str().unwrap(),
        v2_version,
        "v3's jacsPreviousVersion must equal v2's jacsVersion"
    );

    // All three versions must be distinct
    assert_ne!(v1_version, v2_version, "v1 and v2 must differ");
    assert_ne!(v2_version, v3_version, "v2 and v3 must differ");
    assert_ne!(v1_version, v3_version, "v1 and v3 must differ");

    // Verify v3 signature
    let v3_verify = agent.verify_document_signature(&v3_key, None, None, None, None);
    assert!(
        v3_verify.is_ok(),
        "v3 signature verification should succeed: {:?}",
        v3_verify.err()
    );

    // Verify item is completed in v3
    let items = v3_value["jacsTodoItems"].as_array().unwrap();
    assert_eq!(items[0]["status"], "completed");
    assert!(items[0].get("completedDate").is_some());
}

/// Step 67: Archive workflow: add items, complete some, remove completed, add archive ref.
#[test]
fn test_todo_list_archive_workflow() {
    let mut list =
        create_minimal_todo_list("Archive workflow test").expect("Should create todo list");

    // Add several items
    let task_id_1 = add_todo_item(&mut list, "task", "Task one", None).expect("Should add task 1");
    let task_id_2 = add_todo_item(&mut list, "task", "Task two", None).expect("Should add task 2");
    let _task_id_3 =
        add_todo_item(&mut list, "task", "Task three", None).expect("Should add task 3");

    assert_eq!(list["jacsTodoItems"].as_array().unwrap().len(), 3);

    // Complete tasks 1 and 2
    mark_todo_item_complete(&mut list, &task_id_1).expect("Should complete task 1");
    mark_todo_item_complete(&mut list, &task_id_2).expect("Should complete task 2");

    // Remove completed items
    let completed = remove_completed_items(&mut list).expect("Should remove completed items");
    assert_eq!(completed.len(), 2, "Two items should have been removed");

    // Only task 3 should remain
    let remaining = list["jacsTodoItems"].as_array().unwrap();
    assert_eq!(remaining.len(), 1, "One item should remain");
    assert_eq!(remaining[0]["description"], "Task three");

    // Add an archive reference for the old list version
    let archive_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    add_archive_ref(&mut list, archive_uuid).expect("Should add archive ref");

    let refs = list["jacsTodoArchiveRefs"].as_array().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0], archive_uuid);

    // Now sign the archived-state list through the agent
    let mut agent = load_test_agent_one();
    let loaded = agent
        .create_document_and_load(&list.to_string(), None, None)
        .expect("Should sign archived todo list");

    let doc_key = loaded.getkey();
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_result.is_ok(),
        "Archived todo list should verify: {:?}",
        verify_result.err()
    );
}

/// Step 68: Agent creates 2 separate todo lists, both signed independently.
#[test]
fn test_multiple_todo_lists_per_agent() {
    let mut agent = load_test_agent_one();

    // First list
    let mut list1 = create_minimal_todo_list("Work Items").expect("Should create first todo list");
    add_todo_item(&mut list1, "task", "Deploy service", Some("high"))
        .expect("Should add item to list 1");

    let loaded1 = agent
        .create_document_and_load(&list1.to_string(), None, None)
        .expect("Should sign first todo list");
    let key1 = loaded1.getkey();
    let value1 = loaded1.getvalue();

    // Second list
    let mut list2 =
        create_minimal_todo_list("Personal Items").expect("Should create second todo list");
    add_todo_item(&mut list2, "goal", "Learn Rust", Some("medium"))
        .expect("Should add item to list 2");

    let loaded2 = agent
        .create_document_and_load(&list2.to_string(), None, None)
        .expect("Should sign second todo list");
    let key2 = loaded2.getkey();
    let value2 = loaded2.getvalue();

    // Both lists should have distinct IDs
    assert_ne!(
        value1["jacsId"].as_str().unwrap(),
        value2["jacsId"].as_str().unwrap(),
        "Two todo lists must have different jacsId values"
    );

    // Both lists should have signatures
    assert!(
        value1.get("jacsSignature").is_some(),
        "List 1 must be signed"
    );
    assert!(
        value2.get("jacsSignature").is_some(),
        "List 2 must be signed"
    );

    // Both should verify independently
    let verify1 = agent.verify_document_signature(&key1, None, None, None, None);
    assert!(
        verify1.is_ok(),
        "First todo list should verify: {:?}",
        verify1.err()
    );

    let verify2 = agent.verify_document_signature(&key2, None, None, None, None);
    assert!(
        verify2.is_ok(),
        "Second todo list should verify: {:?}",
        verify2.err()
    );

    // Verify correct names are preserved
    assert_eq!(value1["jacsTodoName"], "Work Items");
    assert_eq!(value2["jacsTodoName"], "Personal Items");
}

/// Step 69: Verify all required header fields are present after signing.
#[test]
fn test_todo_list_header_fields_present() {
    let mut agent = load_test_agent_one();

    let mut list = create_minimal_todo_list("Header fields test").expect("Should create todo list");
    add_todo_item(&mut list, "task", "Verify headers", None).expect("Should add item");

    let loaded = agent
        .create_document_and_load(&list.to_string(), None, None)
        .expect("Should load todo list");

    let value = loaded.getvalue();

    // All required header fields must be present
    let required_fields = [
        "jacsId",
        "jacsVersion",
        "jacsVersionDate",
        "jacsOriginalVersion",
        "jacsOriginalDate",
        "jacsType",
        "jacsLevel",
    ];

    for field in &required_fields {
        assert!(
            value.get(*field).is_some() && !value[*field].is_null(),
            "Header field '{}' must be present and non-null in signed todo list",
            field
        );
    }

    // jacsType should be "todo"
    assert_eq!(value["jacsType"], "todo", "jacsType must be 'todo'");

    // jacsLevel should be "config"
    assert_eq!(value["jacsLevel"], "config", "jacsLevel must be 'config'");

    // For a newly created document, jacsOriginalVersion should equal jacsVersion
    assert_eq!(
        value["jacsOriginalVersion"], value["jacsVersion"],
        "For a new document, jacsOriginalVersion must equal jacsVersion"
    );

    // jacsSignature must be present
    assert!(
        value.get("jacsSignature").is_some(),
        "jacsSignature must be present"
    );

    // $schema must be the todo schema URL
    assert_eq!(
        value["$schema"], "https://hai.ai/schemas/todo/v1/todo.schema.json",
        "$schema must reference the todo schema"
    );
}

/// Step 70: Tamper with a signed todo list and verify detection.
#[test]
fn test_todo_list_tamper_detection() {
    let mut agent = load_test_agent_one();

    let mut list =
        create_minimal_todo_list("Tamper detection test").expect("Should create todo list");
    add_todo_item(&mut list, "task", "Original task", None).expect("Should add item");

    let loaded = agent
        .create_document_and_load(&list.to_string(), None, None)
        .expect("Should load and sign todo list");

    let doc_key = loaded.getkey();

    // Verify it is valid before tampering
    let verify_before = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_before.is_ok(),
        "Signature should verify before tampering: {:?}",
        verify_before.err()
    );

    // Tamper with the document
    let original_value = loaded.getvalue().clone();
    let mut tampered = original_value.clone();
    tampered["jacsTodoName"] = json!("TAMPERED NAME");

    // Loading a tampered document with mismatched signatures should fail
    let tampered_string = serde_json::to_string_pretty(&tampered).expect("serialize tampered");
    let tampered_loaded = agent.load_document(&tampered_string);

    assert!(
        tampered_loaded.is_err(),
        "Loading a tampered todo list should fail signature verification"
    );
}

/// Step 71: validate_todo() accepts a valid todo document with header fields.
#[test]
fn test_todo_list_schema_validation() {
    let agent = load_test_agent_one();

    let mut list =
        create_minimal_todo_list("Schema validation test").expect("Should create todo list");

    add_todo_item(&mut list, "goal", "Validate me", Some("high")).expect("Should add item");

    // Add header fields that the schema requires (via allOf with header schema)
    list["jacsId"] = json!("test-todo-id");
    list["jacsVersion"] = json!("test-version-001");
    list["jacsVersionDate"] = json!("2026-02-05T12:00:00Z");
    list["jacsOriginalVersion"] = json!("test-version-001");
    list["jacsOriginalDate"] = json!("2026-02-05T12:00:00Z");

    let result = agent.schema.validate_todo(&list.to_string());
    assert!(
        result.is_ok(),
        "Valid todo list should pass schema validation: {:?}",
        result.err()
    );
}
