//! Messaging tools: send, update, agree, receive.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for sending a signed message to another agent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageSendParams {
    /// The recipient agent's ID (UUID format).
    #[schemars(description = "The JACS agent ID of the recipient (UUID format)")]
    pub recipient_agent_id: String,

    /// The message content to send.
    #[schemars(description = "The message content to send")]
    pub content: String,

    /// The MIME type of the content (default: "text/plain").
    #[schemars(description = "MIME type of the content (default: 'text/plain')")]
    pub content_type: Option<String>,
}

/// Result of sending a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageSendResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The full signed message JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message: Option<String>,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for updating an existing signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageUpdateParams {
    /// The JACS document ID of the message to update.
    #[schemars(description = "JACS document ID of the message to update")]
    pub jacs_id: String,

    /// The new message content.
    #[schemars(description = "Updated message content")]
    pub content: String,

    /// The MIME type of the content (default: "text/plain").
    #[schemars(description = "MIME type of the content (default: 'text/plain')")]
    pub content_type: Option<String>,
}

/// Result of updating a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageUpdateResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The JACS document ID of the updated message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// The full updated signed message JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message: Option<String>,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for agreeing to (co-signing) a received message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageAgreeParams {
    /// The full signed message JSON document to agree to.
    #[schemars(description = "The full signed JSON document to agree to")]
    pub signed_message: String,
}

/// Result of agreeing to a message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageAgreeResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The document ID of the original message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_document_id: Option<String>,

    /// The document ID of the agreement document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_document_id: Option<String>,

    /// The full signed agreement JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_agreement: Option<String>,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for receiving and verifying a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageReceiveParams {
    /// The full signed message JSON document received from another agent.
    #[schemars(description = "The full signed JSON document received from another agent")]
    pub signed_message: String,
}

/// Result of receiving and verifying a signed message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageReceiveResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The sender's agent ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_agent_id: Option<String>,

    /// The extracted message content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// The content MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The message timestamp (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    /// Whether the cryptographic signature is valid.
    pub signature_valid: bool,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the messaging family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_message_send",
            "Create and cryptographically sign a message for sending to another agent. \
             Returns the signed JACS document that can be transmitted to the recipient.",
            schema_map::<MessageSendParams>(),
        ),
        Tool::new(
            "jacs_message_update",
            "Update and re-sign an existing message document with new content.",
            schema_map::<MessageUpdateParams>(),
        ),
        Tool::new(
            "jacs_message_agree",
            "Verify and co-sign (agree to) a received signed message. Creates an agreement \
             document that references the original message.",
            schema_map::<MessageAgreeParams>(),
        ),
        Tool::new(
            "jacs_message_receive",
            "Verify a received signed message and extract its content, sender ID, and timestamp. \
             Use this to validate authenticity before processing a message from another agent.",
            schema_map::<MessageReceiveParams>(),
        ),
    ]
}
