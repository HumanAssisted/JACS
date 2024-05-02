use crate::agent::document::Document;
use crate::Agent;
use chrono::Utc;
use serde_json::{json, Value};
use std::error::Error;
use uuid::Uuid;

/// Creates a minimal message with required fields.
/// # Arguments
///
/// * `content` - The content of the message.
/// * task_id - id of the task this is about
/// * attachments - list of filepaths
/// # Returns
///
/// A `serde_json::Value` representing the created message.
pub fn create_minimal_message(
    agent: &mut Agent,
    content: Value,
    task_id: String,
    // _to: Option<Vec<String>>,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<Value, Box<dyn Error>> {
    let datetime = Utc::now();
    let schema = "https://hai.ai/schemas/message/v1/message.schema.json";

    let mut message = json!({
        "$schema": schema,
        "datetime": datetime.to_rfc3339(),
        "content": content,
        "taskID": task_id
    });

    // optionally add attachements
    if let Some(attachment_list) = attachments {
        let mut files_array: Vec<Value> = Vec::new();

        // Iterate over each attachment
        for attachment_path in attachment_list {
            let final_embed = embed.unwrap_or(false);
            let file_json = agent
                .create_file_json(&attachment_path, final_embed)
                .unwrap();

            // Add the file JSON to the files array
            files_array.push(file_json);
        }

        // Create a new "files" field in the document
        // let instance_map = message.as_object_mut().unwrap();
        message["attachments"] = Value::Array(files_array);
    }
    // sign
    message["signature"] = agent.signing_procedure(&message, None, &"signature".to_string())?;

    message["id"] = json!(Uuid::new_v4().to_string());

    Ok(message)
}
