use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::schema::conversation_crud::{
    create_conversation_message, get_previous_message_id, get_thread_id, start_new_conversation,
};
use serde_json::json;

mod utils;
use utils::load_test_agent_one;

// =============================================================================
// Conversation CRUD Integration Tests
// =============================================================================

/// Test 1: Create a conversation message via CRUD, sign it through the agent
/// pipeline, and verify the signature is valid.
#[test]
fn test_create_and_sign_conversation_message() {
    let mut agent = load_test_agent_one();

    let thread_id = uuid::Uuid::new_v4().to_string();
    let agent_id = agent.get_id().expect("Should get agent id");

    let msg = create_conversation_message(
        &thread_id,
        json!({"body": "Hello, this is a test message"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
        None,
    )
    .expect("Should create conversation message");

    // Verify CRUD output structure
    assert_eq!(msg["threadID"], thread_id);
    assert_eq!(msg["jacsType"], "message");
    assert_eq!(msg["jacsLevel"], "raw");
    assert_eq!(
        msg["$schema"],
        "https://hai.ai/schemas/message/v1/message.schema.json"
    );

    // Sign through the agent pipeline
    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should load and sign conversation message");

    let doc_key = loaded.getkey();
    let value = loaded.getvalue();

    // Must have a signature
    assert!(
        value.get("jacsSignature").is_some(),
        "Signed message must have jacsSignature"
    );

    // Verify the signature
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_result.is_ok(),
        "Signature verification should succeed: {:?}",
        verify_result.err()
    );
}

/// Test 2: Start a new conversation, sign the first message, and verify.
#[test]
fn test_start_new_conversation_and_sign() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let (msg, thread_id) = start_new_conversation(
        json!({"body": "Starting a new conversation"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
    )
    .expect("Should start new conversation");

    // The thread_id should be a valid non-empty UUID
    assert!(!thread_id.is_empty(), "Thread ID should not be empty");

    // The message should reference the generated thread_id
    assert_eq!(msg["threadID"], thread_id);

    // The first message should have no previous message ID
    assert!(
        msg.get("jacsMessagePreviousId").is_none(),
        "First message in a conversation should have no jacsMessagePreviousId"
    );

    // Sign through the agent pipeline
    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should load and sign first conversation message");

    let doc_key = loaded.getkey();
    let value = loaded.getvalue();

    assert!(
        value.get("jacsSignature").is_some(),
        "Signed first message must have jacsSignature"
    );
    assert!(
        value.get("jacsId").is_some(),
        "Signed message must have jacsId"
    );
    assert!(
        value.get("jacsVersion").is_some(),
        "Signed message must have jacsVersion"
    );

    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_result.is_ok(),
        "First message signature verification should succeed: {:?}",
        verify_result.err()
    );
}

/// Test 3: Create a chain of 3 messages in a thread, each referencing the
/// previous via jacsMessagePreviousId. Sign all messages and verify all.
#[test]
fn test_conversation_thread_chain() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // Message 1: start the conversation
    let (msg1, thread_id) = start_new_conversation(
        json!({"body": "First message in thread"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation");

    let loaded1 = agent
        .create_document_and_load(&msg1.to_string(), None, None)
        .expect("Should sign message 1");
    let key1 = loaded1.getkey();
    let value1 = loaded1.getvalue().clone();
    let msg1_id = value1["jacsId"]
        .as_str()
        .expect("Message 1 should have jacsId")
        .to_string();

    // Message 2: references message 1
    let msg2 = create_conversation_message(
        &thread_id,
        json!({"body": "Second message in thread"}),
        vec![agent_id.clone()],
        vec!["recipient@example.com".to_string()],
        Some(&msg1_id),
    )
    .expect("Should create message 2");

    assert_eq!(msg2["jacsMessagePreviousId"], msg1_id);

    let loaded2 = agent
        .create_document_and_load(&msg2.to_string(), None, None)
        .expect("Should sign message 2");
    let key2 = loaded2.getkey();
    let value2 = loaded2.getvalue().clone();
    let msg2_id = value2["jacsId"]
        .as_str()
        .expect("Message 2 should have jacsId")
        .to_string();

    // Message 3: references message 2
    let msg3 = create_conversation_message(
        &thread_id,
        json!({"body": "Third message in thread"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id.clone()],
        Some(&msg2_id),
    )
    .expect("Should create message 3");

    assert_eq!(msg3["jacsMessagePreviousId"], msg2_id);

    let loaded3 = agent
        .create_document_and_load(&msg3.to_string(), None, None)
        .expect("Should sign message 3");
    let key3 = loaded3.getkey();
    let value3 = loaded3.getvalue().clone();
    let msg3_id = value3["jacsId"]
        .as_str()
        .expect("Message 3 should have jacsId")
        .to_string();

    // All messages should share the same thread ID
    assert_eq!(value1["threadID"], thread_id);
    assert_eq!(value2["threadID"], thread_id);
    assert_eq!(value3["threadID"], thread_id);

    // All message IDs should be distinct
    assert_ne!(msg1_id, msg2_id, "Message 1 and 2 must have different IDs");
    assert_ne!(msg2_id, msg3_id, "Message 2 and 3 must have different IDs");
    assert_ne!(msg1_id, msg3_id, "Message 1 and 3 must have different IDs");

    // Verify chain linkage
    assert!(
        value1.get("jacsMessagePreviousId").is_none()
            || value1["jacsMessagePreviousId"].is_null(),
        "First message should not have a previous message ID"
    );
    assert_eq!(
        value2["jacsMessagePreviousId"], msg1_id,
        "Message 2 should reference message 1"
    );
    assert_eq!(
        value3["jacsMessagePreviousId"], msg2_id,
        "Message 3 should reference message 2"
    );

    // Verify all signatures independently
    let verify1 = agent.verify_document_signature(&key1, None, None, None, None);
    assert!(
        verify1.is_ok(),
        "Message 1 signature verification should succeed: {:?}",
        verify1.err()
    );

    let verify2 = agent.verify_document_signature(&key2, None, None, None, None);
    assert!(
        verify2.is_ok(),
        "Message 2 signature verification should succeed: {:?}",
        verify2.err()
    );

    let verify3 = agent.verify_document_signature(&key3, None, None, None, None);
    assert!(
        verify3.is_ok(),
        "Message 3 signature verification should succeed: {:?}",
        verify3.err()
    );
}

/// Test 4: Verify that conversation messages with jacsLevel "raw" are
/// immutable -- update_document should fail. Conversation progression
/// happens by creating new messages that reference the previous one,
/// not by mutating existing messages.
#[test]
fn test_conversation_message_immutability() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let (msg, _thread_id) = start_new_conversation(
        json!({"body": "Original message content"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation");

    // Sign the original message
    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign message");

    let doc_key = loaded.getkey();
    let original_value = loaded.getvalue().clone();

    // Confirm the message is level "raw" (immutable)
    assert_eq!(
        original_value["jacsLevel"], "raw",
        "Conversation messages should have jacsLevel 'raw'"
    );

    // Attempting to update a raw document should fail
    let mut modified = original_value.clone();
    modified["content"] = json!({"body": "Attempted modification"});

    let update_result = agent.update_document(&doc_key, &modified.to_string(), None, None);
    assert!(
        update_result.is_err(),
        "Updating a raw (immutable) conversation message should fail"
    );

    // The correct pattern is to create a new message referencing the original
    let original_id = original_value["jacsId"]
        .as_str()
        .expect("Should have jacsId")
        .to_string();
    let thread_id = original_value["threadID"]
        .as_str()
        .expect("Should have threadID")
        .to_string();

    let follow_up = create_conversation_message(
        &thread_id,
        json!({"body": "Corrected content in a follow-up message"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
        Some(&original_id),
    )
    .expect("Should create follow-up message");

    let follow_up_loaded = agent
        .create_document_and_load(&follow_up.to_string(), None, None)
        .expect("Should sign follow-up message");

    let follow_up_value = follow_up_loaded.getvalue();

    // Follow-up references the original
    assert_eq!(
        follow_up_value["jacsMessagePreviousId"], original_id,
        "Follow-up must reference the original message"
    );
    // Follow-up has a different document ID
    assert_ne!(
        follow_up_value["jacsId"], original_id,
        "Follow-up must have a distinct jacsId"
    );
    // Follow-up shares the same thread
    assert_eq!(
        follow_up_value["threadID"], thread_id,
        "Follow-up must be in the same thread"
    );
}

/// Test 5: Create a message, sign it, retrieve it, and verify that
/// the threadID field is preserved through the signing pipeline.
#[test]
fn test_conversation_thread_id_preserved() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let thread_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    let msg = create_conversation_message(
        thread_id,
        json!({"body": "Thread preservation test"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
        None,
    )
    .expect("Should create conversation message");

    // Verify the CRUD function set the thread ID
    assert_eq!(
        get_thread_id(&msg),
        Some(thread_id.to_string()),
        "get_thread_id should return the thread ID from the CRUD output"
    );

    // Sign and load
    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign message");

    let doc_key = loaded.getkey();

    // Retrieve the document back from the agent's store
    let retrieved = agent
        .get_document(&doc_key)
        .expect("Should retrieve signed message");

    let retrieved_value = retrieved.getvalue();

    // Thread ID must be preserved through the full pipeline
    assert_eq!(
        retrieved_value["threadID"], thread_id,
        "threadID must be preserved after signing and retrieval"
    );
    assert_eq!(
        get_thread_id(retrieved_value),
        Some(thread_id.to_string()),
        "get_thread_id must work on the retrieved document"
    );
}

/// Test 6: Create a message with a previous message ID, sign it, retrieve it,
/// and verify that jacsMessagePreviousId is preserved.
#[test]
fn test_conversation_previous_id_preserved() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let thread_id = uuid::Uuid::new_v4().to_string();
    let previous_id = uuid::Uuid::new_v4().to_string();

    let msg = create_conversation_message(
        &thread_id,
        json!({"body": "Previous ID preservation test"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
        Some(&previous_id),
    )
    .expect("Should create conversation message with previous ID");

    // Verify the CRUD function set the previous message ID
    assert_eq!(
        get_previous_message_id(&msg),
        Some(previous_id.clone()),
        "get_previous_message_id should return the ID from the CRUD output"
    );

    // Sign and load
    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign message with previous ID");

    let doc_key = loaded.getkey();

    // Retrieve the document back
    let retrieved = agent
        .get_document(&doc_key)
        .expect("Should retrieve signed message");

    let retrieved_value = retrieved.getvalue();

    // jacsMessagePreviousId must be preserved
    assert_eq!(
        retrieved_value["jacsMessagePreviousId"], previous_id,
        "jacsMessagePreviousId must be preserved after signing and retrieval"
    );
    assert_eq!(
        get_previous_message_id(retrieved_value),
        Some(previous_id),
        "get_previous_message_id must work on the retrieved document"
    );
}

/// Test 7: Create and sign a conversation message, tamper with the content,
/// and verify that loading the tampered document fails signature verification.
#[test]
fn test_conversation_message_tamper_detection() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let (msg, _thread_id) = start_new_conversation(
        json!({"body": "Original untampered content"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
    )
    .expect("Should start conversation");

    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign message");

    let doc_key = loaded.getkey();

    // Verify it is valid before tampering
    let verify_before = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_before.is_ok(),
        "Signature should verify before tampering: {:?}",
        verify_before.err()
    );

    // Tamper with the document content
    let original_value = loaded.getvalue().clone();
    let mut tampered = original_value.clone();
    tampered["content"] = json!({"body": "TAMPERED MESSAGE CONTENT"});

    // Loading a tampered document should fail signature verification
    let tampered_string = serde_json::to_string_pretty(&tampered).expect("serialize tampered");
    let tampered_loaded = agent.load_document(&tampered_string);

    assert!(
        tampered_loaded.is_err(),
        "Loading a tampered conversation message should fail signature verification"
    );
}

/// Test 8: Create messages in two different threads and verify they are
/// independent -- different thread IDs and separate document identities.
#[test]
fn test_multiple_conversations() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // Conversation 1
    let (msg1, thread_id_1) = start_new_conversation(
        json!({"body": "Message in conversation 1"}),
        vec!["alice@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation 1");

    let loaded1 = agent
        .create_document_and_load(&msg1.to_string(), None, None)
        .expect("Should sign conversation 1 message");
    let key1 = loaded1.getkey();
    let value1 = loaded1.getvalue();

    // Conversation 2
    let (msg2, thread_id_2) = start_new_conversation(
        json!({"body": "Message in conversation 2"}),
        vec!["bob@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation 2");

    let loaded2 = agent
        .create_document_and_load(&msg2.to_string(), None, None)
        .expect("Should sign conversation 2 message");
    let key2 = loaded2.getkey();
    let value2 = loaded2.getvalue();

    // Thread IDs must be different
    assert_ne!(
        thread_id_1, thread_id_2,
        "Two conversations must have different thread IDs"
    );
    assert_ne!(
        value1["threadID"], value2["threadID"],
        "Signed documents must have different threadIDs"
    );

    // Document IDs must be different
    assert_ne!(
        value1["jacsId"], value2["jacsId"],
        "Messages in different conversations must have different jacsId values"
    );

    // Both must have valid signatures
    assert!(value1.get("jacsSignature").is_some(), "Message 1 must be signed");
    assert!(value2.get("jacsSignature").is_some(), "Message 2 must be signed");

    let verify1 = agent.verify_document_signature(&key1, None, None, None, None);
    assert!(
        verify1.is_ok(),
        "Conversation 1 message should verify: {:?}",
        verify1.err()
    );

    let verify2 = agent.verify_document_signature(&key2, None, None, None, None);
    assert!(
        verify2.is_ok(),
        "Conversation 2 message should verify: {:?}",
        verify2.err()
    );

    // Verify correct content is preserved
    assert_eq!(value1["content"]["body"], "Message in conversation 1");
    assert_eq!(value2["content"]["body"], "Message in conversation 2");
}

/// Test 9: Create a conversation message with rich content containing various
/// fields, sign it, and verify all content is preserved.
#[test]
fn test_conversation_with_rich_content() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let rich_content = json!({
        "body": "This is a detailed message with structured content",
        "subject": "Project Update",
        "priority": "high",
        "metadata": {
            "source": "automated-system",
            "version": 2,
            "tags": ["urgent", "review-needed"]
        }
    });

    let (msg, thread_id) = start_new_conversation(
        rich_content.clone(),
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
        ],
        vec![agent_id],
    )
    .expect("Should create message with rich content");

    // Sign through the agent pipeline
    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign rich content message");

    let doc_key = loaded.getkey();
    let value = loaded.getvalue();

    // All content fields must be preserved
    assert_eq!(
        value["content"]["body"],
        "This is a detailed message with structured content"
    );
    assert_eq!(value["content"]["subject"], "Project Update");
    assert_eq!(value["content"]["priority"], "high");
    assert_eq!(value["content"]["metadata"]["source"], "automated-system");
    assert_eq!(value["content"]["metadata"]["version"], 2);

    let tags = value["content"]["metadata"]["tags"]
        .as_array()
        .expect("tags should be an array");
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0], "urgent");
    assert_eq!(tags[1], "review-needed");

    // Multiple recipients must be preserved
    let to = value["to"]
        .as_array()
        .expect("to should be an array");
    assert_eq!(to.len(), 2);
    assert_eq!(to[0], "alice@example.com");
    assert_eq!(to[1], "bob@example.com");

    // Thread ID must be preserved
    assert_eq!(value["threadID"], thread_id);

    // Signature must be valid
    let verify_result = agent.verify_document_signature(&doc_key, None, None, None, None);
    assert!(
        verify_result.is_ok(),
        "Rich content message signature should verify: {:?}",
        verify_result.err()
    );
}

/// Test 10: Verify that empty `to` or `from` arrays are rejected by the
/// CRUD functions at the application level.
#[test]
fn test_empty_recipients_rejected() {
    // Empty "to" should be rejected
    let result_empty_to = create_conversation_message(
        "some-thread-id",
        json!({"body": "Test"}),
        vec![],
        vec!["sender@example.com".to_string()],
        None,
    );
    assert!(
        result_empty_to.is_err(),
        "Empty 'to' array should be rejected"
    );

    // Empty "from" should be rejected
    let result_empty_from = create_conversation_message(
        "some-thread-id",
        json!({"body": "Test"}),
        vec!["recipient@example.com".to_string()],
        vec![],
        None,
    );
    assert!(
        result_empty_from.is_err(),
        "Empty 'from' array should be rejected"
    );

    // Both empty should be rejected
    let result_both_empty = create_conversation_message(
        "some-thread-id",
        json!({"body": "Test"}),
        vec![],
        vec![],
        None,
    );
    assert!(
        result_both_empty.is_err(),
        "Both empty 'to' and 'from' should be rejected"
    );

    // Empty thread ID should be rejected
    let result_empty_thread = create_conversation_message(
        "",
        json!({"body": "Test"}),
        vec!["recipient@example.com".to_string()],
        vec!["sender@example.com".to_string()],
        None,
    );
    assert!(
        result_empty_thread.is_err(),
        "Empty thread ID should be rejected"
    );

    // Also verify start_new_conversation rejects empty arrays
    let result_start_empty_to = start_new_conversation(
        json!({"body": "Test"}),
        vec![],
        vec!["sender@example.com".to_string()],
    );
    assert!(
        result_start_empty_to.is_err(),
        "start_new_conversation should reject empty 'to'"
    );

    let result_start_empty_from = start_new_conversation(
        json!({"body": "Test"}),
        vec!["recipient@example.com".to_string()],
        vec![],
    );
    assert!(
        result_start_empty_from.is_err(),
        "start_new_conversation should reject empty 'from'"
    );
}

/// Test: Verify all required JACS header fields are present after signing
/// a conversation message.
#[test]
fn test_conversation_message_header_fields_present() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    let (msg, _thread_id) = start_new_conversation(
        json!({"body": "Header fields test"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id],
    )
    .expect("Should start conversation");

    let loaded = agent
        .create_document_and_load(&msg.to_string(), None, None)
        .expect("Should sign message");

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
            "Header field '{}' must be present and non-null in signed conversation message",
            field
        );
    }

    // jacsType should be "message"
    assert_eq!(
        value["jacsType"], "message",
        "jacsType must be 'message'"
    );

    // jacsLevel should be "raw"
    assert_eq!(
        value["jacsLevel"], "raw",
        "jacsLevel must be 'raw'"
    );

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

    // $schema must be the message schema URL
    assert_eq!(
        value["$schema"],
        "https://hai.ai/schemas/message/v1/message.schema.json",
        "$schema must reference the message schema"
    );
}

/// Test: Verify get_thread_id and get_previous_message_id helper functions
/// work correctly on signed documents retrieved from the agent store.
#[test]
fn test_conversation_helper_functions_on_signed_docs() {
    let mut agent = load_test_agent_one();
    let agent_id = agent.get_id().expect("Should get agent id");

    // Create and sign a first message
    let (msg1, thread_id) = start_new_conversation(
        json!({"body": "First"}),
        vec!["recipient@example.com".to_string()],
        vec![agent_id.clone()],
    )
    .expect("Should start conversation");

    let loaded1 = agent
        .create_document_and_load(&msg1.to_string(), None, None)
        .expect("Should sign message 1");

    let msg1_id = loaded1.getvalue()["jacsId"]
        .as_str()
        .expect("Should have jacsId")
        .to_string();

    // get_thread_id should work on the signed document
    assert_eq!(
        get_thread_id(loaded1.getvalue()),
        Some(thread_id.clone()),
        "get_thread_id should work on signed document"
    );

    // get_previous_message_id should return None for first message
    assert_eq!(
        get_previous_message_id(loaded1.getvalue()),
        None,
        "First message should have no previous message ID"
    );

    // Create and sign a second message with previous_id set
    let msg2 = create_conversation_message(
        &thread_id,
        json!({"body": "Second"}),
        vec![agent_id.clone()],
        vec!["recipient@example.com".to_string()],
        Some(&msg1_id),
    )
    .expect("Should create message 2");

    let loaded2 = agent
        .create_document_and_load(&msg2.to_string(), None, None)
        .expect("Should sign message 2");

    // get_previous_message_id should return the first message's ID
    assert_eq!(
        get_previous_message_id(loaded2.getvalue()),
        Some(msg1_id),
        "Second message should reference first message"
    );
    assert_eq!(
        get_thread_id(loaded2.getvalue()),
        Some(thread_id),
        "Second message should share the same thread ID"
    );
}
