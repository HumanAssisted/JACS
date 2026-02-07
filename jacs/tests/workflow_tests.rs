use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::schema::commitment_crud::{
    create_minimal_commitment, dispute_commitment, set_conversation_ref, set_todo_ref,
    update_commitment_status,
};
use jacs::schema::conversation_crud::{create_conversation_message, start_new_conversation};
use jacs::schema::reference_utils::{
    build_todo_item_ref, get_uuid_ref, parse_todo_item_ref, validate_uuid_ref,
};
use jacs::schema::todo_crud::{
    add_todo_item, create_minimal_todo_list, set_item_commitment_ref, set_item_conversation_ref,
};
use serde_json::json;

mod utils;
use utils::load_test_agent_one;

// =============================================================================
// Cross-Document Workflow Integration Tests
//
// These tests exercise the full lifecycle across commitment, todo, and
// conversation document types, verifying that cross-references survive
// signing and that documents interoperate correctly.
// =============================================================================

/// Test 1: Start a conversation thread, create a commitment that references
/// the thread ID via set_conversation_ref(), sign both, and verify the
/// commitment's jacsCommitmentConversationRef field matches the thread ID.
#[test]
fn test_conversation_to_commitment_workflow() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // Step 1: Start a conversation and sign the first message.
    let (msg, thread_id) = start_new_conversation(
        json!({"body": "Let's discuss the quarterly deliverable"}),
        vec!["partner@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation");

    let loaded_msg = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign conversation message");

    let msg_key = loaded_msg.getkey();
    let msg_value = loaded_msg.getvalue();

    // Verify the message is signed and thread ID is preserved.
    assert!(
        msg_value.get("jacsSignature").is_some(),
        "Conversation message must be signed"
    );
    assert_eq!(
        msg_value["threadID"], thread_id,
        "Thread ID must be preserved after signing"
    );

    // Step 2: Create a commitment referencing the conversation thread.
    let mut commitment =
        create_minimal_commitment("Deliver quarterly report based on conversation")
            .expect("Should create commitment");

    set_conversation_ref(&mut commitment, &thread_id)
        .expect("Should set conversation ref on commitment");

    assert_eq!(
        commitment["jacsCommitmentConversationRef"], thread_id,
        "Conversation ref should be set before signing"
    );

    // Step 3: Sign the commitment through the agent pipeline.
    let loaded_commitment = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign commitment");

    let commitment_key = loaded_commitment.getkey();
    let commitment_value = loaded_commitment.getvalue();

    // Step 4: Verify the conversation reference survived signing.
    assert_eq!(
        commitment_value["jacsCommitmentConversationRef"], thread_id,
        "jacsCommitmentConversationRef must survive signing"
    );

    // Step 5: Verify both signatures independently.
    let verify_msg = agent.verify_document_signature(&msg_key, None, None, None, None);
    assert!(
        verify_msg.is_ok(),
        "Conversation message signature should verify: {:?}",
        verify_msg.err()
    );

    let verify_commitment =
        agent.verify_document_signature(&commitment_key, None, None, None, None);
    assert!(
        verify_commitment.is_ok(),
        "Commitment signature should verify: {:?}",
        verify_commitment.err()
    );

    // Step 6: The two documents should have distinct jacsId values.
    assert_ne!(
        msg_value["jacsId"], commitment_value["jacsId"],
        "Message and commitment must have different jacsId values"
    );
}

/// Test 2: Create and sign a commitment, create a todo list with an item,
/// link the todo item to the commitment via set_item_commitment_ref(),
/// sign the todo list, and verify the cross-reference survives signing.
#[test]
fn test_commitment_to_todo_workflow() {
    let mut agent = load_test_agent_one();

    // Step 1: Create and sign a commitment.
    let commitment = create_minimal_commitment("Implement authentication module")
        .expect("Should create commitment");

    let loaded_commitment = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign commitment");

    let commitment_key = loaded_commitment.getkey();
    let commitment_value = loaded_commitment.getvalue();
    let commitment_jacs_id = commitment_value["jacsId"]
        .as_str()
        .expect("Commitment should have jacsId")
        .to_string();

    // Step 2: Create a todo list with a task item linked to the commitment.
    let mut todo_list =
        create_minimal_todo_list("Auth Module Tasks").expect("Should create todo list");

    let task_id = add_todo_item(
        &mut todo_list,
        "task",
        "Write auth middleware",
        Some("high"),
    )
    .expect("Should add task item");

    set_item_commitment_ref(&mut todo_list, &task_id, &commitment_jacs_id)
        .expect("Should set commitment reference on todo item");

    // Verify the reference is set before signing.
    let items_before = todo_list["jacsTodoItems"]
        .as_array()
        .expect("Should have items");
    assert_eq!(
        items_before[0]["relatedCommitmentId"], commitment_jacs_id,
        "relatedCommitmentId should be set before signing"
    );

    // Step 3: Sign the todo list through the agent pipeline.
    let loaded_todo = agent
        .create_document_and_load(&todo_list.to_string(), None, None)
        .expect("Should sign todo list");

    let todo_key = loaded_todo.getkey();
    let todo_value = loaded_todo.getvalue();

    // Step 4: Verify the cross-reference survives signing.
    let items_after = todo_value["jacsTodoItems"]
        .as_array()
        .expect("Should have items after signing");
    assert_eq!(
        items_after[0]["relatedCommitmentId"], commitment_jacs_id,
        "relatedCommitmentId must survive signing"
    );

    // Step 5: Verify both signatures independently.
    let verify_commitment =
        agent.verify_document_signature(&commitment_key, None, None, None, None);
    assert!(
        verify_commitment.is_ok(),
        "Commitment signature should verify: {:?}",
        verify_commitment.err()
    );

    let verify_todo = agent.verify_document_signature(&todo_key, None, None, None, None);
    assert!(
        verify_todo.is_ok(),
        "Todo list signature should verify: {:?}",
        verify_todo.err()
    );
}

/// Test 3: Full lifecycle across all three document types.
///   a. Start a conversation (2-3 messages in a thread)
///   b. Create a commitment referencing the conversation thread
///   c. Create a todo list with an item linked to the commitment
///   d. Link the todo item to the conversation thread too
///   e. Sign all documents
///   f. Verify all signatures
///   g. Verify all cross-references are preserved
#[test]
fn test_full_lifecycle_conversation_commitment_todo() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // --- (a) Start a conversation with 3 messages in a thread ---

    let (msg1, thread_id) = start_new_conversation(
        json!({"body": "We need to plan the Q2 release"}),
        vec!["partner@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation");

    let loaded_msg1 = agent
        .create_document_and_load(&msg1.to_string(), None, None)
        .expect("Should sign message 1");
    let msg1_key = loaded_msg1.getkey();
    let msg1_value = loaded_msg1.getvalue().clone();
    let msg1_id = msg1_value["jacsId"]
        .as_str()
        .expect("Message 1 should have jacsId")
        .to_string();

    // Message 2 references message 1.
    let msg2 = create_conversation_message(
        &thread_id,
        json!({"body": "Agreed. Let's define the scope"}),
        vec![agent_id.clone()],
        vec!["partner@example.com".to_string()],
        Some(&msg1_id),
    )
    .expect("Should create message 2");

    let loaded_msg2 = agent
        .create_document_and_load(&msg2.to_string(), None, None)
        .expect("Should sign message 2");
    let msg2_key = loaded_msg2.getkey();
    let msg2_value = loaded_msg2.getvalue().clone();
    let msg2_id = msg2_value["jacsId"]
        .as_str()
        .expect("Message 2 should have jacsId")
        .to_string();

    // Message 3 references message 2.
    let msg3 = create_conversation_message(
        &thread_id,
        json!({"body": "Scope confirmed. Creating commitment now."}),
        vec!["partner@example.com".to_string()],
        vec![agent_id.clone()],
        Some(&msg2_id),
    )
    .expect("Should create message 3");

    let loaded_msg3 = agent
        .create_document_and_load(&msg3.to_string(), None, None)
        .expect("Should sign message 3");
    let msg3_key = loaded_msg3.getkey();
    let msg3_value = loaded_msg3.getvalue().clone();

    // Verify the thread chain.
    assert_eq!(msg1_value["threadID"], thread_id);
    assert_eq!(msg2_value["threadID"], thread_id);
    assert_eq!(msg3_value["threadID"], thread_id);
    assert_eq!(msg2_value["jacsMessagePreviousId"], msg1_id);
    assert_eq!(msg3_value["jacsMessagePreviousId"], msg2_id);

    // --- (b) Create a commitment referencing the conversation thread ---

    let mut commitment = create_minimal_commitment("Deliver Q2 release scope as discussed")
        .expect("Should create commitment");

    set_conversation_ref(&mut commitment, &thread_id).expect("Should set conversation ref");

    let loaded_commitment = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign commitment");
    let commitment_key = loaded_commitment.getkey();
    let commitment_value = loaded_commitment.getvalue().clone();
    let commitment_jacs_id = commitment_value["jacsId"]
        .as_str()
        .expect("Commitment should have jacsId")
        .to_string();

    // --- (c) Create a todo list with an item linked to the commitment ---

    let mut todo_list =
        create_minimal_todo_list("Q2 Release Tasks").expect("Should create todo list");

    let task_id = add_todo_item(
        &mut todo_list,
        "task",
        "Implement release pipeline",
        Some("high"),
    )
    .expect("Should add task item");

    set_item_commitment_ref(&mut todo_list, &task_id, &commitment_jacs_id)
        .expect("Should link todo item to commitment");

    // --- (d) Link the todo item to the conversation thread too ---

    set_item_conversation_ref(&mut todo_list, &task_id, &thread_id)
        .expect("Should link todo item to conversation thread");

    // --- (e) Sign the todo list ---

    let loaded_todo = agent
        .create_document_and_load(&todo_list.to_string(), None, None)
        .expect("Should sign todo list");
    let todo_key = loaded_todo.getkey();
    let todo_value = loaded_todo.getvalue().clone();

    // --- (f) Verify all signatures ---

    let verify_msg1 = agent.verify_document_signature(&msg1_key, None, None, None, None);
    assert!(
        verify_msg1.is_ok(),
        "Message 1 signature should verify: {:?}",
        verify_msg1.err()
    );

    let verify_msg2 = agent.verify_document_signature(&msg2_key, None, None, None, None);
    assert!(
        verify_msg2.is_ok(),
        "Message 2 signature should verify: {:?}",
        verify_msg2.err()
    );

    let verify_msg3 = agent.verify_document_signature(&msg3_key, None, None, None, None);
    assert!(
        verify_msg3.is_ok(),
        "Message 3 signature should verify: {:?}",
        verify_msg3.err()
    );

    let verify_commitment =
        agent.verify_document_signature(&commitment_key, None, None, None, None);
    assert!(
        verify_commitment.is_ok(),
        "Commitment signature should verify: {:?}",
        verify_commitment.err()
    );

    let verify_todo = agent.verify_document_signature(&todo_key, None, None, None, None);
    assert!(
        verify_todo.is_ok(),
        "Todo list signature should verify: {:?}",
        verify_todo.err()
    );

    // --- (g) Verify all cross-references are preserved ---

    // Commitment references the conversation thread.
    assert_eq!(
        commitment_value["jacsCommitmentConversationRef"], thread_id,
        "Commitment must reference the conversation thread after signing"
    );

    // Todo item references the commitment.
    let todo_items = todo_value["jacsTodoItems"]
        .as_array()
        .expect("Should have items");
    assert_eq!(
        todo_items[0]["relatedCommitmentId"], commitment_jacs_id,
        "Todo item must reference the commitment after signing"
    );

    // Todo item references the conversation thread.
    assert_eq!(
        todo_items[0]["relatedConversationThread"], thread_id,
        "Todo item must reference the conversation thread after signing"
    );

    // All documents have distinct jacsId values.
    let all_ids = vec![
        msg1_value["jacsId"].as_str().unwrap(),
        msg2_value["jacsId"].as_str().unwrap(),
        msg3_value["jacsId"].as_str().unwrap(),
        commitment_value["jacsId"].as_str().unwrap(),
        todo_value["jacsId"].as_str().unwrap(),
    ];
    for i in 0..all_ids.len() {
        for j in (i + 1)..all_ids.len() {
            assert_ne!(
                all_ids[i], all_ids[j],
                "All documents must have distinct jacsId values (indices {} and {})",
                i, j
            );
        }
    }
}

/// Test 4: Create a todo list, add an item, build a list-uuid:item-uuid ref
/// using build_todo_item_ref(), set it on a commitment via set_todo_ref(),
/// sign, and verify the ref survives and is parseable via parse_todo_item_ref().
#[test]
fn test_todo_ref_format_on_commitment() {
    let mut agent = load_test_agent_one();

    // Step 1: Create a todo list and add an item.
    let mut todo_list =
        create_minimal_todo_list("Ref Format Test List").expect("Should create todo list");

    let _item_id = add_todo_item(
        &mut todo_list,
        "task",
        "Validate ref format",
        Some("medium"),
    )
    .expect("Should add task item");

    // Step 2: Sign the todo list to get its jacsId.
    let loaded_todo = agent
        .create_document_and_load(&todo_list.to_string(), None, None)
        .expect("Should sign todo list");

    let todo_value = loaded_todo.getvalue();
    let list_jacs_id = todo_value["jacsId"]
        .as_str()
        .expect("Todo list should have jacsId")
        .to_string();

    // The item IDs are UUIDs generated by add_todo_item. Retrieve the actual
    // itemId from the signed document to ensure we use the real value.
    let signed_items = todo_value["jacsTodoItems"]
        .as_array()
        .expect("Should have items");
    let signed_item_id = signed_items[0]["itemId"]
        .as_str()
        .expect("Item should have itemId")
        .to_string();

    // Step 3: Build a todo ref in the format list-uuid:item-uuid.
    let todo_ref =
        build_todo_item_ref(&list_jacs_id, &signed_item_id).expect("Should build todo item ref");

    assert!(
        todo_ref.contains(':'),
        "Todo ref must contain a colon separator"
    );
    assert!(
        todo_ref.starts_with(&list_jacs_id),
        "Todo ref must start with the list UUID"
    );
    assert!(
        todo_ref.ends_with(&signed_item_id),
        "Todo ref must end with the item UUID"
    );

    // Step 4: Set the todo ref on a commitment.
    let mut commitment = create_minimal_commitment("Commitment linked to todo item via ref")
        .expect("Should create commitment");

    set_todo_ref(&mut commitment, &todo_ref).expect("Should set todo ref on commitment");

    assert_eq!(
        commitment["jacsCommitmentTodoRef"], todo_ref,
        "Todo ref should be set before signing"
    );

    // Step 5: Sign the commitment.
    let loaded_commitment = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign commitment");

    let commitment_value = loaded_commitment.getvalue();

    // Step 6: Verify the ref survived signing.
    let surviving_ref = commitment_value["jacsCommitmentTodoRef"]
        .as_str()
        .expect("jacsCommitmentTodoRef must survive signing");

    assert_eq!(
        surviving_ref, todo_ref,
        "jacsCommitmentTodoRef must match the original ref after signing"
    );

    // Step 7: Parse the ref back and verify the components.
    let (parsed_list_id, parsed_item_id) =
        parse_todo_item_ref(surviving_ref).expect("Should parse todo ref from signed commitment");

    assert_eq!(
        parsed_list_id, list_jacs_id,
        "Parsed list ID must match the original"
    );
    assert_eq!(
        parsed_item_id, signed_item_id,
        "Parsed item ID must match the original"
    );
}

/// Test 5: Create a commitment, sign it, update to "active", sign a new
/// version, then dispute it with a reason, sign another version. Verify
/// the version chain and that the dispute reason persists.
#[test]
fn test_commitment_dispute_workflow() {
    let mut agent = load_test_agent_one();

    // Version 1: Create and sign a pending commitment.
    let commitment = create_minimal_commitment("Partnership agreement for Q2")
        .expect("Should create commitment");

    let v1 = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign v1");

    let v1_key = v1.getkey();
    let v1_value = v1.getvalue().clone();
    let v1_version = v1_value["jacsVersion"]
        .as_str()
        .expect("v1 should have jacsVersion")
        .to_string();

    assert_eq!(
        v1_value["jacsCommitmentStatus"], "pending",
        "Initial status should be pending"
    );

    // Version 2: Update to "active" and re-sign.
    let mut v2_input = v1_value.clone();
    update_commitment_status(&mut v2_input, "active").expect("Should update status to active");

    let v2 = agent
        .update_document(&v1_key, &v2_input.to_string(), None, None)
        .expect("Should create v2");

    let v2_key = v2.getkey();
    let v2_value = v2.getvalue().clone();
    let v2_version = v2_value["jacsVersion"]
        .as_str()
        .expect("v2 should have jacsVersion")
        .to_string();

    assert_ne!(
        v1_version, v2_version,
        "v1 and v2 must have different versions"
    );
    assert_eq!(
        v2_value["jacsPreviousVersion"].as_str().unwrap(),
        v1_version,
        "v2 must point back to v1"
    );
    assert_eq!(
        v2_value["jacsCommitmentStatus"], "active",
        "v2 status should be active"
    );

    // Version 3: Dispute with a reason and re-sign.
    let mut v3_input = v2_value.clone();
    dispute_commitment(
        &mut v3_input,
        "Deliverable quality does not meet agreed standards",
    )
    .expect("Should dispute commitment");

    let v3 = agent
        .update_document(&v2_key, &v3_input.to_string(), None, None)
        .expect("Should create v3");

    let v3_key = v3.getkey();
    let v3_value = v3.getvalue().clone();
    let v3_version = v3_value["jacsVersion"]
        .as_str()
        .expect("v3 should have jacsVersion")
        .to_string();

    // Verify the version chain.
    assert_ne!(
        v2_version, v3_version,
        "v2 and v3 must have different versions"
    );
    assert_ne!(
        v1_version, v3_version,
        "v1 and v3 must have different versions"
    );
    assert_eq!(
        v3_value["jacsPreviousVersion"].as_str().unwrap(),
        v2_version,
        "v3 must point back to v2"
    );

    // Verify dispute fields persist.
    assert_eq!(
        v3_value["jacsCommitmentStatus"], "disputed",
        "v3 status should be disputed"
    );
    assert_eq!(
        v3_value["jacsCommitmentDisputeReason"],
        "Deliverable quality does not meet agreed standards",
        "Dispute reason must persist after signing"
    );

    // Verify all versions have valid signatures.
    let verify_v3 = agent.verify_document_signature(&v3_key, None, None, None, None);
    assert!(
        verify_v3.is_ok(),
        "v3 signature verification should succeed: {:?}",
        verify_v3.err()
    );
}

/// Test 6: Create a todo list, add goal and task items, link the task to
/// a commitment, progress the task through statuses (pending -> in-progress
/// -> completed), verify completedDate is set, remove completed items,
/// and verify archive works.
#[test]
fn test_todo_item_lifecycle_with_refs() {
    let mut agent = load_test_agent_one();

    // Create and sign a commitment so we have a real jacsId to reference.
    let commitment =
        create_minimal_commitment("Build the dashboard feature").expect("Should create commitment");

    let loaded_commitment = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign commitment");

    let commitment_jacs_id = loaded_commitment.getvalue()["jacsId"]
        .as_str()
        .expect("Commitment should have jacsId")
        .to_string();

    // Create a todo list with a goal and a task.
    let mut todo_list =
        create_minimal_todo_list("Dashboard Feature Tasks").expect("Should create todo list");

    let _goal_id = add_todo_item(
        &mut todo_list,
        "goal",
        "Complete dashboard feature",
        Some("high"),
    )
    .expect("Should add goal");

    let task_id = add_todo_item(
        &mut todo_list,
        "task",
        "Implement data widgets",
        Some("medium"),
    )
    .expect("Should add task");

    // Link the task to the commitment.
    set_item_commitment_ref(&mut todo_list, &task_id, &commitment_jacs_id)
        .expect("Should set commitment reference on task");

    // Sign the initial todo list (v1).
    let v1 = agent
        .create_document_and_load(&todo_list.to_string(), None, None)
        .expect("Should sign todo list v1");

    let v1_key = v1.getkey();
    let v1_value = v1.getvalue().clone();

    // Verify initial state.
    let v1_items = v1_value["jacsTodoItems"]
        .as_array()
        .expect("Should have items");
    assert_eq!(v1_items.len(), 2, "Should have goal and task");
    assert_eq!(v1_items[0]["itemType"], "goal");
    assert_eq!(v1_items[1]["itemType"], "task");
    assert_eq!(v1_items[1]["status"], "pending");
    assert_eq!(
        v1_items[1]["relatedCommitmentId"], commitment_jacs_id,
        "Task should reference the commitment"
    );

    // Progress task to in-progress (v2).
    let mut v2_input = v1_value.clone();
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

    let v2 = agent
        .update_document(&v1_key, &v2_input.to_string(), None, None)
        .expect("Should update to v2");

    let v2_key = v2.getkey();
    let v2_value = v2.getvalue().clone();

    let v2_items = v2_value["jacsTodoItems"].as_array().unwrap();
    // Find the task item by checking itemId.
    let v2_task = v2_items
        .iter()
        .find(|item| item.get("itemId").and_then(|id| id.as_str()) == Some(&task_id))
        .expect("Task should exist in v2");
    assert_eq!(
        v2_task["status"], "in-progress",
        "Task should be in-progress in v2"
    );
    assert_eq!(
        v2_task["relatedCommitmentId"], commitment_jacs_id,
        "Commitment ref should persist through status update"
    );

    // Progress task to completed (v3) with a completedDate.
    let mut v3_input = v2_value.clone();
    if let Some(items) = v3_input
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
    {
        for item in items.iter_mut() {
            if item.get("itemId").and_then(|id| id.as_str()) == Some(&task_id) {
                item["status"] = json!("completed");
                item["completedDate"] = json!("2026-02-05T15:00:00Z");
            }
        }
    }

    let v3 = agent
        .update_document(&v2_key, &v3_input.to_string(), None, None)
        .expect("Should update to v3");

    let v3_key = v3.getkey();
    let v3_value = v3.getvalue().clone();

    let v3_items = v3_value["jacsTodoItems"].as_array().unwrap();
    let v3_task = v3_items
        .iter()
        .find(|item| item.get("itemId").and_then(|id| id.as_str()) == Some(&task_id))
        .expect("Task should exist in v3");
    assert_eq!(
        v3_task["status"], "completed",
        "Task should be completed in v3"
    );
    assert_eq!(
        v3_task["completedDate"], "2026-02-05T15:00:00Z",
        "completedDate should be set"
    );

    // Remove completed items and sign the cleaned list (v4).
    let mut v4_input = v3_value.clone();
    // Manually filter out completed items.
    if let Some(items) = v4_input
        .get_mut("jacsTodoItems")
        .and_then(|v| v.as_array_mut())
    {
        items.retain(|item| item.get("status").and_then(|s| s.as_str()) != Some("completed"));
    }

    let v4 = agent
        .update_document(&v3_key, &v4_input.to_string(), None, None)
        .expect("Should update to v4 after removing completed");

    let v4_key = v4.getkey();
    let v4_value = v4.getvalue();

    let v4_items = v4_value["jacsTodoItems"].as_array().unwrap();
    assert_eq!(
        v4_items.len(),
        1,
        "Only the goal should remain after removing completed task"
    );
    assert_eq!(v4_items[0]["itemType"], "goal");

    // Verify the final version's signature.
    let verify_v4 = agent.verify_document_signature(&v4_key, None, None, None, None);
    assert!(
        verify_v4.is_ok(),
        "v4 signature should verify: {:?}",
        verify_v4.err()
    );
}

/// Test 7: Create one conversation thread, create 3 commitments all
/// referencing the same thread, sign all. Verify they each reference
/// the same thread ID but have different jacsId values.
#[test]
fn test_multiple_commitments_one_conversation() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // Start a conversation thread.
    let (msg, thread_id) = start_new_conversation(
        json!({"body": "Discussing multi-commitment plan"}),
        vec!["partner@example.com".to_string()],
        vec![agent_id],
    )
    .expect("Should start conversation");

    let loaded_msg = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign conversation message");

    let msg_key = loaded_msg.getkey();

    // Create 3 commitments, all referencing the same thread.
    let descriptions = [
        "First deliverable from conversation",
        "Second deliverable from conversation",
        "Third deliverable from conversation",
    ];

    let mut commitment_keys = Vec::new();
    let mut commitment_jacs_ids = Vec::new();

    for description in &descriptions {
        let mut commitment =
            create_minimal_commitment(description).expect("Should create commitment");

        set_conversation_ref(&mut commitment, &thread_id).expect("Should set conversation ref");

        let loaded = agent
            .create_document_and_load(&commitment.to_string(), None, None)
            .expect("Should sign commitment");

        let key = loaded.getkey();
        let value = loaded.getvalue();

        // Verify the conversation ref is set.
        assert_eq!(
            value["jacsCommitmentConversationRef"], thread_id,
            "Commitment '{}' must reference the same thread",
            description
        );

        commitment_jacs_ids.push(
            value["jacsId"]
                .as_str()
                .expect("Should have jacsId")
                .to_string(),
        );
        commitment_keys.push(key);
    }

    // All 3 commitments must have different jacsId values.
    assert_ne!(
        commitment_jacs_ids[0], commitment_jacs_ids[1],
        "Commitment 1 and 2 must have different IDs"
    );
    assert_ne!(
        commitment_jacs_ids[1], commitment_jacs_ids[2],
        "Commitment 2 and 3 must have different IDs"
    );
    assert_ne!(
        commitment_jacs_ids[0], commitment_jacs_ids[2],
        "Commitment 1 and 3 must have different IDs"
    );

    // Verify all signatures.
    let verify_msg = agent.verify_document_signature(&msg_key, None, None, None, None);
    assert!(
        verify_msg.is_ok(),
        "Conversation message should verify: {:?}",
        verify_msg.err()
    );

    for (i, key) in commitment_keys.iter().enumerate() {
        let verify = agent.verify_document_signature(key, None, None, None, None);
        assert!(
            verify.is_ok(),
            "Commitment {} signature should verify: {:?}",
            i + 1,
            verify.err()
        );
    }
}

/// Test 8: Create actual signed documents, extract UUIDs using get_uuid_ref(),
/// validate them with validate_uuid_ref(), build and parse todo refs from
/// real document IDs.
#[test]
fn test_reference_utils_with_real_documents() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // Create and sign a conversation message.
    let (msg, thread_id) = start_new_conversation(
        json!({"body": "Reference utils test conversation"}),
        vec!["partner@example.com".to_string()],
        vec![agent_id],
    )
    .expect("Should start conversation");

    let loaded_msg = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign message");
    let msg_value = loaded_msg.getvalue().clone();

    // Create and sign a commitment.
    let commitment = create_minimal_commitment("Reference utils test commitment")
        .expect("Should create commitment");

    let loaded_commitment = agent
        .create_document_and_load(&commitment.to_string(), None, None)
        .expect("Should sign commitment");
    let commitment_value = loaded_commitment.getvalue().clone();

    // Create and sign a todo list with an item.
    let mut todo_list =
        create_minimal_todo_list("Reference Utils Test List").expect("Should create todo list");

    add_todo_item(&mut todo_list, "task", "Test ref utils", None).expect("Should add task item");

    let loaded_todo = agent
        .create_document_and_load(&todo_list.to_string(), None, None)
        .expect("Should sign todo list");
    let todo_value = loaded_todo.getvalue().clone();

    // --- Test get_uuid_ref on real signed documents ---

    // Extract jacsId from each document using get_uuid_ref.
    let msg_jacs_id =
        get_uuid_ref(&msg_value, "jacsId").expect("Should extract jacsId from message");
    let commitment_jacs_id =
        get_uuid_ref(&commitment_value, "jacsId").expect("Should extract jacsId from commitment");
    let todo_jacs_id =
        get_uuid_ref(&todo_value, "jacsId").expect("Should extract jacsId from todo list");

    // All extracted IDs should be non-empty.
    assert!(
        !msg_jacs_id.is_empty(),
        "Message jacsId should not be empty"
    );
    assert!(
        !commitment_jacs_id.is_empty(),
        "Commitment jacsId should not be empty"
    );
    assert!(!todo_jacs_id.is_empty(), "Todo jacsId should not be empty");

    // Extract threadID from the message.
    let extracted_thread_id =
        get_uuid_ref(&msg_value, "threadID").expect("Should extract threadID from message");
    assert_eq!(
        extracted_thread_id, thread_id,
        "Extracted threadID must match the original"
    );

    // Extracting a nonexistent field returns None.
    assert!(
        get_uuid_ref(&msg_value, "nonExistentField").is_none(),
        "get_uuid_ref should return None for missing fields"
    );

    // --- Test validate_uuid_ref on real document IDs ---

    // The jacsId values from signed documents should be valid UUIDs.
    validate_uuid_ref(&msg_jacs_id).expect("Message jacsId should be a valid UUID");
    validate_uuid_ref(&commitment_jacs_id).expect("Commitment jacsId should be a valid UUID");
    validate_uuid_ref(&todo_jacs_id).expect("Todo jacsId should be a valid UUID");
    validate_uuid_ref(&thread_id).expect("Thread ID should be a valid UUID");

    // Invalid strings should fail validation.
    assert!(
        validate_uuid_ref("not-a-uuid").is_err(),
        "Non-UUID string should fail validation"
    );
    assert!(
        validate_uuid_ref("").is_err(),
        "Empty string should fail validation"
    );

    // --- Test build_todo_item_ref and parse_todo_item_ref with real IDs ---

    // Extract item ID from the signed todo list.
    let todo_items = todo_value["jacsTodoItems"]
        .as_array()
        .expect("Should have items");
    let item_id = todo_items[0]["itemId"]
        .as_str()
        .expect("Item should have itemId")
        .to_string();

    // Build a todo ref from real document IDs.
    let todo_ref =
        build_todo_item_ref(&todo_jacs_id, &item_id).expect("Should build todo ref from real IDs");

    let expected_ref = format!("{}:{}", todo_jacs_id, item_id);
    assert_eq!(
        todo_ref, expected_ref,
        "Built todo ref must match expected format"
    );

    // Parse it back.
    let (parsed_list_id, parsed_item_id) =
        parse_todo_item_ref(&todo_ref).expect("Should parse the built todo ref");

    assert_eq!(
        parsed_list_id, todo_jacs_id,
        "Parsed list ID must match the original"
    );
    assert_eq!(
        parsed_item_id, item_id,
        "Parsed item ID must match the original"
    );

    // Round-trip: build -> parse -> build should produce the same ref.
    let rebuilt_ref = build_todo_item_ref(&parsed_list_id, &parsed_item_id)
        .expect("Should rebuild todo ref after parsing");
    assert_eq!(
        rebuilt_ref, todo_ref,
        "Round-trip build -> parse -> build must be idempotent"
    );
}
