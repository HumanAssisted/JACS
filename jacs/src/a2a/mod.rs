//! A2A (Agent-to-Agent) protocol integration for JACS
//!
//! This module provides functionality to integrate JACS with Google's A2A protocol,
//! positioning JACS as a cryptographic provenance extension to A2A.

pub mod agent_card;
pub mod extension;
pub mod keys;
pub mod provenance;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;

/// A2A protocol version constant
pub const A2A_PROTOCOL_VERSION: &str = "1.0";

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

/// A2A Agent Card structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub protocol_version: String,
    pub url: String,
    pub name: String,
    pub description: String,
    pub skills: Vec<Skill>,
    pub security_schemes: Vec<SecurityScheme>,
    pub capabilities: Capabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A2A Skill structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

/// A2A Security Scheme
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecurityScheme {
    pub r#type: String,
    pub scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
}

/// A2A Capabilities
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Capabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<Extension>>,
}

/// A2A Extension
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Extension {
    pub uri: String,
    pub description: String,
    pub required: bool,
    pub params: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_serialization() {
        let agent_card = AgentCard {
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            url: "https://agent.example.com".to_string(),
            name: "Example Agent".to_string(),
            description: "An example JACS-enabled agent".to_string(),
            skills: vec![],
            security_schemes: vec![],
            capabilities: Capabilities { extensions: None },
            metadata: None,
        };

        let json = serde_json::to_string(&agent_card).unwrap();
        let _deserialized: AgentCard = serde_json::from_str(&json).unwrap();
    }
}
