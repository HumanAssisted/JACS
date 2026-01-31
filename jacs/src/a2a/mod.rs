//! A2A (Agent-to-Agent) protocol integration for JACS
//!
//! This module provides functionality to integrate JACS with the A2A protocol,
//! positioning JACS as a cryptographic provenance extension to A2A.
//!
//! Implements A2A protocol v0.4.0 (September 2025).

pub mod agent_card;
pub mod extension;
pub mod keys;
pub mod provenance;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;

/// A2A protocol version constant (v0.4.0)
pub const A2A_PROTOCOL_VERSION: &str = "0.4.0";

/// JACS extension URI for A2A
pub const JACS_EXTENSION_URI: &str = "urn:hai.ai:jacs-provenance-v1";

/// Common A2A error type
#[derive(Debug)]
pub enum A2AError {
    SerializationError(String),
    SigningError(String),
    ValidationError(String),
    KeyGenerationError(String),
}

impl std::fmt::Display for A2AError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            A2AError::SerializationError(msg) => write!(f, "A2A serialization error: {}", msg),
            A2AError::SigningError(msg) => write!(f, "A2A signing error: {}", msg),
            A2AError::ValidationError(msg) => write!(f, "A2A validation error: {}", msg),
            A2AError::KeyGenerationError(msg) => write!(f, "A2A key generation error: {}", msg),
        }
    }
}

impl Error for A2AError {}

// ---------------------------------------------------------------------------
// AgentCard and related types (A2A v0.4.0)
// ---------------------------------------------------------------------------

/// A2A Agent Card structure (v0.4.0)
///
/// Published at `/.well-known/agent-card.json` for zero-config discovery.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    // Required fields
    pub name: String,
    pub description: String,
    pub version: String,
    pub protocol_versions: Vec<String>,
    pub supported_interfaces: Vec<AgentInterface>,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub capabilities: AgentCapabilities,
    pub skills: Vec<AgentSkill>,
    // Optional fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_schemes: Option<HashMap<String, SecurityScheme>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<AgentCardSignature>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A Agent Interface — declares a reachable endpoint with its protocol binding.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    pub protocol_binding: String, // "jsonrpc", "grpc", "rest"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// A2A Agent Provider info.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentProvider {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

/// A2A Agent Skill (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<Value>>,
}

/// A2A Security Scheme — tagged union with 5 variants (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SecurityScheme {
    #[serde(rename = "apiKey")]
    ApiKey {
        /// Where the key is sent: "header" or "query"
        #[serde(rename = "in")]
        location: String,
        /// Name of the header or query parameter
        name: String,
    },
    #[serde(rename = "http")]
    Http {
        /// Auth scheme, e.g. "Bearer" or "Basic"
        scheme: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        bearer_format: Option<String>,
    },
    #[serde(rename = "oauth2")]
    OAuth2 {
        /// OAuth 2.0 flows configuration
        flows: Value,
    },
    #[serde(rename = "openIdConnect")]
    OpenIdConnect { open_id_connect_url: String },
    #[serde(rename = "mutualTLS")]
    MutualTls {},
}

/// A2A Agent Capabilities (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_agent_card: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<AgentExtension>>,
}

/// A2A Agent Extension declaration (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentExtension {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// JWS signature embedded in an AgentCard (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentCardSignature {
    /// JWS compact serialization (RFC 7515)
    pub jws: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

// ---------------------------------------------------------------------------
// A2A Task / Message / Artifact types
// ---------------------------------------------------------------------------

/// A2A Task state enum (ProtoJSON: SCREAMING_SNAKE_CASE)
#[allow(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TaskState {
    TASK_STATE_UNSPECIFIED,
    TASK_STATE_SUBMITTED,
    TASK_STATE_WORKING,
    TASK_STATE_COMPLETED,
    TASK_STATE_FAILED,
    TASK_STATE_CANCELLED,
    TASK_STATE_INPUT_REQUIRED,
    TASK_STATE_REJECTED,
    TASK_STATE_AUTH_REQUIRED,
}

/// A2A Role enum (ProtoJSON: SCREAMING_SNAKE_CASE)
#[allow(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Role {
    ROLE_UNSPECIFIED,
    ROLE_USER,
    ROLE_AGENT,
}

/// A2A Part — the smallest content unit.
///
/// In the proto spec this is a `oneof`; here we use optional fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A Artifact (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct A2AArtifact {
    pub artifact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parts: Vec<Part>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

/// A2A Message (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct A2AMessage {
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub role: Role,
    pub parts: Vec<Part>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_task_ids: Option<Vec<String>>,
}

/// A2A Task Status (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    pub state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2AMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// A2A Task (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct A2ATask {
    pub id: String,
    pub context_id: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<A2AArtifact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<A2AMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

// ---------------------------------------------------------------------------
// A2A Protocol Errors
// ---------------------------------------------------------------------------

/// Standard A2A protocol error types (v0.4.0)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum A2AProtocolError {
    TaskNotFoundError,
    TaskNotCancelableError,
    PushNotificationNotSupportedError,
    UnsupportedOperationError,
    ContentTypeNotSupportedError,
    InvalidAgentResponseError,
    ExtendedAgentCardNotConfiguredError,
    ExtensionSupportRequiredError,
    VersionNotSupportedError,
}

impl std::fmt::Display for A2AProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            A2AProtocolError::TaskNotFoundError => write!(f, "Task not found"),
            A2AProtocolError::TaskNotCancelableError => write!(f, "Task not cancelable"),
            A2AProtocolError::PushNotificationNotSupportedError => {
                write!(f, "Push notifications not supported")
            }
            A2AProtocolError::UnsupportedOperationError => write!(f, "Unsupported operation"),
            A2AProtocolError::ContentTypeNotSupportedError => {
                write!(f, "Content type not supported")
            }
            A2AProtocolError::InvalidAgentResponseError => write!(f, "Invalid agent response"),
            A2AProtocolError::ExtendedAgentCardNotConfiguredError => {
                write!(f, "Extended agent card not configured")
            }
            A2AProtocolError::ExtensionSupportRequiredError => {
                write!(f, "Extension support required")
            }
            A2AProtocolError::VersionNotSupportedError => write!(f, "Version not supported"),
        }
    }
}

impl Error for A2AProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_serialization() {
        let agent_card = AgentCard {
            name: "Example Agent".to_string(),
            description: "An example JACS-enabled agent".to_string(),
            version: "1.0.0".to_string(),
            protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            supported_interfaces: vec![AgentInterface {
                url: "https://agent.jacs.localhost".to_string(),
                protocol_binding: "jsonrpc".to_string(),
                tenant: None,
            }],
            default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
            capabilities: AgentCapabilities {
                streaming: None,
                push_notifications: None,
                extended_agent_card: None,
                extensions: None,
            },
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security: None,
            signatures: None,
            metadata: None,
        };

        let json = serde_json::to_string(&agent_card).unwrap();
        let deserialized: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.protocol_versions[0], A2A_PROTOCOL_VERSION);
    }

    #[test]
    fn test_security_scheme_variants() {
        // ApiKey variant
        let api_key = SecurityScheme::ApiKey {
            location: "header".to_string(),
            name: "X-API-Key".to_string(),
        };
        let json = serde_json::to_string(&api_key).unwrap();
        assert!(json.contains("\"type\":\"apiKey\""));
        let _: SecurityScheme = serde_json::from_str(&json).unwrap();

        // Http variant
        let http = SecurityScheme::Http {
            scheme: "Bearer".to_string(),
            bearer_format: Some("JWT".to_string()),
        };
        let json = serde_json::to_string(&http).unwrap();
        assert!(json.contains("\"type\":\"http\""));
        let _: SecurityScheme = serde_json::from_str(&json).unwrap();

        // MutualTls variant
        let mtls = SecurityScheme::MutualTls {};
        let json = serde_json::to_string(&mtls).unwrap();
        assert!(json.contains("\"type\":\"mutualTLS\""));
        let _: SecurityScheme = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_task_state_serialization() {
        let state = TaskState::TASK_STATE_COMPLETED;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"TASK_STATE_COMPLETED\"");
    }

    #[test]
    fn test_a2a_artifact_round_trip() {
        let artifact = A2AArtifact {
            artifact_id: "art-123".to_string(),
            name: Some("Test artifact".to_string()),
            description: None,
            parts: vec![Part {
                text: Some("hello".to_string()),
                data: None,
                url: None,
                media_type: Some("text/plain".to_string()),
                filename: None,
                metadata: None,
            }],
            metadata: None,
            extensions: None,
        };

        let json = serde_json::to_string(&artifact).unwrap();
        let deserialized: A2AArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.artifact_id, "art-123");
        assert_eq!(deserialized.parts[0].text, Some("hello".to_string()));
    }

    #[test]
    fn test_a2a_message_round_trip() {
        let message = A2AMessage {
            message_id: "msg-456".to_string(),
            context_id: Some("ctx-1".to_string()),
            task_id: None,
            role: Role::ROLE_USER,
            parts: vec![Part {
                text: Some("What is the weather?".to_string()),
                data: None,
                url: None,
                media_type: None,
                filename: None,
                metadata: None,
            }],
            metadata: None,
            extensions: None,
            reference_task_ids: None,
        };

        let json = serde_json::to_string(&message).unwrap();
        let deserialized: A2AMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message_id, "msg-456");
        assert_eq!(deserialized.role, Role::ROLE_USER);
    }
}
