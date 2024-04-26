use serde_json::{json, Value};
use uuid::Uuid;

/// Creates a minimal message with required fields.
///
/// # Arguments
///
/// * `datetime` - The datetime of the message.
/// * `content` - The content of the message.
///
/// # Returns
///
/// A `serde_json::Value` representing the created message.
fn create_minimal_message(datetime: &str, content: Value) -> Value {
    let mut message = json!({
        "datetime": datetime,
        "content": content,
    });

    message["id"] = json!(Uuid::new_v4().to_string());
    message
}
