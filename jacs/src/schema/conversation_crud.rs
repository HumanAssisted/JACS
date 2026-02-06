use serde_json::{Value, json};
use uuid::Uuid;

/// Creates a conversation message with thread and ordering support.
///
/// # Arguments
///
/// * `thread_id` - UUID of the conversation thread.
/// * `content` - Message content object.
/// * `to` - Recipients.
/// * `from` - Senders.
/// * `previous_message_id` - Optional UUID of the previous message in this thread.
pub fn create_conversation_message(
    thread_id: &str,
    content: Value,
    to: Vec<String>,
    from: Vec<String>,
    previous_message_id: Option<&str>,
) -> Result<Value, String> {
    if thread_id.is_empty() {
        return Err("Thread ID cannot be empty".to_string());
    }
    if to.is_empty() {
        return Err("Recipients (to) cannot be empty".to_string());
    }
    if from.is_empty() {
        return Err("Senders (from) cannot be empty".to_string());
    }

    let mut msg = json!({
        "$schema": "https://hai.ai/schemas/message/v1/message.schema.json",
        "threadID": thread_id,
        "content": content,
        "to": to,
        "from": from,
        "jacsType": "message",
        "jacsLevel": "raw",
    });

    if let Some(prev_id) = previous_message_id {
        msg["jacsMessagePreviousId"] = json!(prev_id);
    }

    Ok(msg)
}

/// Starts a new conversation by generating a thread ID and creating the first message.
/// Returns (message_value, thread_id).
pub fn start_new_conversation(
    content: Value,
    to: Vec<String>,
    from: Vec<String>,
) -> Result<(Value, String), String> {
    let thread_id = Uuid::new_v4().to_string();
    let msg = create_conversation_message(&thread_id, content, to, from, None)?;
    Ok((msg, thread_id))
}

/// Extracts the thread ID from a message document.
pub fn get_thread_id(message: &Value) -> Option<String> {
    message
        .get("threadID")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extracts the previous message ID from a message document.
pub fn get_previous_message_id(message: &Value) -> Option<String> {
    message
        .get("jacsMessagePreviousId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_conversation_message() {
        let msg = create_conversation_message(
            "thread-uuid",
            json!({"body": "Hello"}),
            vec!["agent-b".to_string()],
            vec!["agent-a".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(msg["threadID"], "thread-uuid");
        assert_eq!(msg["content"]["body"], "Hello");
        assert_eq!(msg["to"][0], "agent-b");
        assert_eq!(msg["from"][0], "agent-a");
        assert!(msg.get("jacsMessagePreviousId").is_none());
    }

    #[test]
    fn test_create_conversation_message_with_previous() {
        let msg = create_conversation_message(
            "thread-uuid",
            json!({"body": "Reply"}),
            vec!["agent-a".to_string()],
            vec!["agent-b".to_string()],
            Some("prev-msg-uuid"),
        )
        .unwrap();
        assert_eq!(msg["jacsMessagePreviousId"], "prev-msg-uuid");
    }

    #[test]
    fn test_start_new_conversation() {
        let (msg, thread_id) = start_new_conversation(
            json!({"body": "Let's talk"}),
            vec!["agent-b".to_string()],
            vec!["agent-a".to_string()],
        )
        .unwrap();
        assert!(!thread_id.is_empty());
        assert_eq!(msg["threadID"], thread_id);
    }

    #[test]
    fn test_get_thread_id() {
        let msg = json!({"threadID": "my-thread"});
        assert_eq!(get_thread_id(&msg), Some("my-thread".to_string()));
    }

    #[test]
    fn test_get_previous_message_id() {
        let msg = json!({"jacsMessagePreviousId": "prev-id"});
        assert_eq!(
            get_previous_message_id(&msg),
            Some("prev-id".to_string())
        );
        let msg2 = json!({});
        assert_eq!(get_previous_message_id(&msg2), None);
    }

    #[test]
    fn test_empty_thread_id_rejected() {
        let result = create_conversation_message(
            "",
            json!({"body": "Hi"}),
            vec!["agent-b".to_string()],
            vec!["agent-a".to_string()],
            None,
        );
        assert!(result.is_err());
    }
}
