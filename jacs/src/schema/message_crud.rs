use crate::Agent;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::error::JacsError;
use crate::time_utils;
use serde_json::{Value, json};

/// Creates a minimal message with required fields.
/// message are immutable and signed so theres no update method
/// A `serde_json::Value` representing the created message.
pub fn create_message(
    agent: &mut Agent,
    content: Value,
    to: Vec<String>,
    from: Vec<String>,
    outbound: Option<bool>,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<JACSDocument, JacsError> {
    let datetime = time_utils::now_rfc3339();
    let schema = "https://hai.ai/schemas/message/v1/message.schema.json";

    let message = json!({
        "$schema": schema,
        "datetime": datetime,
        "content": content,
        "to": to,
        "from": from,
        "outbound": outbound.unwrap_or(false),
    });
    // convert to json string
    let message_str = serde_json::to_string(&message)?;
    // create doc with schema checking and attachments using standard JacsDocument
    let message: JACSDocument = agent.create_document_and_load(&message_str, attachments, embed)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_message_builds_a_signed_document_with_defaults() {
        let mut agent = Agent::ephemeral("ring-Ed25519").expect("agent should construct");
        let agent_json = crate::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .expect("agent fixture should be created");
        agent
            .create_agent_and_load(&agent_json, true, Some("ring-Ed25519"))
            .expect("agent should be initialized with keys");

        let message = create_message(
            &mut agent,
            json!({"text": "hello"}),
            vec!["agent-b".to_string()],
            vec!["agent-a".to_string()],
            None,
            None,
            None,
        )
        .expect("message should be created");

        assert_eq!(
            message.getschema().unwrap(),
            "https://hai.ai/schemas/message/v1/message.schema.json",
        );
        assert_eq!(message.getvalue()["content"], json!({"text": "hello"}));
        assert_eq!(message.getvalue()["to"], json!(vec!["agent-b"]));
        assert_eq!(message.getvalue()["from"], json!(vec!["agent-a"]));
        assert_eq!(message.getvalue()["outbound"], json!(false));
    }
}
