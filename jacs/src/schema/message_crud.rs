use crate::Agent;
use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::time_utils;
use serde_json::{Value, json};
use std::error::Error;

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
) -> Result<JACSDocument, Box<dyn Error>> {
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
