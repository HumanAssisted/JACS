//! HAI client for interacting with HAI.ai
//!
//! This module provides a minimal, clean API for connecting to HAI services:
//! - `testconnection()` - verify connectivity to the HAI server
//! - `register()` - register a JACS agent with HAI
//!
//! # Example
//!
//! ```rust,ignore
//! use jacs_binding_core::hai::{HaiClient, HaiError};
//! use jacs_binding_core::AgentWrapper;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), HaiError> {
//!     let client = HaiClient::new("https://api.hai.ai")
//!         .with_api_key("your-api-key");
//!
//!     // Test connectivity
//!     if client.testconnection().await? {
//!         println!("Connected to HAI");
//!     }
//!
//!     // Register an agent
//!     let agent = AgentWrapper::new();
//!     agent.load("/path/to/config.json".to_string()).unwrap();
//!     let result = client.register(&agent).await?;
//!     println!("Registered: {}", result.agent_id);
//!     Ok(())
//! }
//! ```

use crate::AgentWrapper;
use serde::{Deserialize, Serialize};
use std::fmt;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur when interacting with HAI services.
#[derive(Debug)]
pub enum HaiError {
    /// Failed to connect to the HAI server.
    ConnectionFailed(String),
    /// Agent registration failed.
    RegistrationFailed(String),
    /// Authentication is required but not provided.
    AuthRequired,
    /// Invalid response from server.
    InvalidResponse(String),
}

impl fmt::Display for HaiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HaiError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            HaiError::RegistrationFailed(msg) => write!(f, "Registration failed: {}", msg),
            HaiError::AuthRequired => write!(f, "Authentication required: provide an API key"),
            HaiError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
        }
    }
}

impl std::error::Error for HaiError {}

// =============================================================================
// Response Types
// =============================================================================

/// Signature information returned from HAI registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaiSignature {
    /// Key identifier used for signing.
    pub key_id: String,
    /// Algorithm used (e.g., "Ed25519", "ECDSA-P256").
    pub algorithm: String,
    /// Base64-encoded signature.
    pub signature: String,
    /// ISO 8601 timestamp of when the signature was created.
    pub signed_at: String,
}

/// Result of a successful agent registration with HAI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    /// The agent's unique identifier.
    pub agent_id: String,
    /// The JACS document ID assigned by HAI.
    pub jacs_id: String,
    /// Whether DNS verification was successful.
    pub dns_verified: bool,
    /// Signatures from HAI attesting to the registration.
    pub signatures: Vec<HaiSignature>,
}

/// Result of checking agent registration status with HAI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    /// Whether the agent is registered with HAI.ai.
    pub registered: bool,
    /// The agent's JACS ID (if registered).
    #[serde(default)]
    pub agent_id: String,
    /// HAI.ai registration ID (if registered).
    #[serde(default)]
    pub registration_id: String,
    /// When the agent was registered (if registered), as ISO 8601 timestamp.
    #[serde(default)]
    pub registered_at: String,
    /// List of HAI signature IDs (if registered).
    #[serde(default)]
    pub hai_signatures: Vec<String>,
}

// =============================================================================
// Internal Request/Response Types
// =============================================================================

#[derive(Serialize)]
struct RegisterRequest {
    agent_json: String,
}

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
}

// =============================================================================
// HAI Client
// =============================================================================

/// Client for interacting with HAI.ai services.
///
/// Use the builder pattern to configure the client:
/// ```rust,ignore
/// let client = HaiClient::new("https://api.hai.ai")
///     .with_api_key("your-key");
/// ```
pub struct HaiClient {
    endpoint: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl HaiClient {
    /// Create a new HAI client targeting the specified endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Base URL of the HAI API (e.g., "https://api.hai.ai")
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_key: None,
            client: reqwest::Client::new(),
        }
    }

    /// Set the API key for authentication.
    ///
    /// This is required for most operations.
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.api_key = Some(api_key.to_string());
        self
    }

    /// Get the endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Test connectivity to the HAI server.
    ///
    /// Returns `Ok(true)` if the server is reachable and healthy.
    ///
    /// # Errors
    ///
    /// Returns `HaiError::ConnectionFailed` if the server cannot be reached
    /// or returns an unhealthy status.
    pub async fn testconnection(&self) -> Result<bool, HaiError> {
        let url = format!("{}/health", self.endpoint);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(HaiError::ConnectionFailed(format!(
                "Server returned status: {}",
                response.status()
            )));
        }

        // Try to parse health response, but accept any 2xx as success
        match response.json::<HealthResponse>().await {
            Ok(health) => Ok(health.status == "ok" || health.status == "healthy"),
            Err(_) => Ok(true), // 2xx without JSON body is still success
        }
    }

    /// Register a JACS agent with HAI.
    ///
    /// The agent must be loaded and have valid keys before registration.
    ///
    /// # Arguments
    ///
    /// * `agent` - A loaded `AgentWrapper` with valid cryptographic keys
    ///
    /// # Errors
    ///
    /// - `HaiError::AuthRequired` - No API key was provided
    /// - `HaiError::RegistrationFailed` - The agent could not be registered
    /// - `HaiError::InvalidResponse` - The server returned an unexpected response
    pub async fn register(&self, agent: &AgentWrapper) -> Result<RegistrationResult, HaiError> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or(HaiError::AuthRequired)?;

        // Get the agent JSON from the wrapper
        let agent_json = agent
            .get_agent_json()
            .map_err(|e| HaiError::RegistrationFailed(e.to_string()))?;

        let url = format!("{}/v1/agents/register", self.endpoint);

        let request = RegisterRequest { agent_json };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            return Err(HaiError::RegistrationFailed(format!(
                "Status {}: {}",
                status, body
            )));
        }

        response
            .json::<RegistrationResult>()
            .await
            .map_err(|e| HaiError::InvalidResponse(e.to_string()))
    }

    /// Check registration status of an agent with HAI.
    ///
    /// Queries the HAI API to determine if the agent is registered
    /// and retrieves registration details if so.
    ///
    /// # Arguments
    ///
    /// * `agent` - A loaded `AgentWrapper` to check status for
    ///
    /// # Returns
    ///
    /// `StatusResult` with registration details. If the agent is not registered,
    /// `registered` will be `false`.
    ///
    /// # Errors
    ///
    /// - `HaiError::AuthRequired` - No API key was provided
    /// - `HaiError::ConnectionFailed` - Could not connect to HAI server
    /// - `HaiError::InvalidResponse` - The server returned an unexpected response
    pub async fn status(&self, agent: &AgentWrapper) -> Result<StatusResult, HaiError> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or(HaiError::AuthRequired)?;

        // Get the agent JSON and extract the ID
        let agent_json = agent
            .get_agent_json()
            .map_err(|e| HaiError::InvalidResponse(format!("Failed to get agent JSON: {}", e)))?;

        let agent_value: serde_json::Value = serde_json::from_str(&agent_json)
            .map_err(|e| HaiError::InvalidResponse(format!("Failed to parse agent JSON: {}", e)))?;

        let agent_id = agent_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HaiError::InvalidResponse("Agent JSON missing jacsId field".to_string()))?
            .to_string();

        let url = format!("{}/v1/agents/{}/status", self.endpoint, agent_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| HaiError::ConnectionFailed(e.to_string()))?;

        // Handle 404 as "not registered"
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(StatusResult {
                registered: false,
                agent_id,
                registration_id: String::new(),
                registered_at: String::new(),
                hai_signatures: Vec::new(),
            });
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            return Err(HaiError::InvalidResponse(format!(
                "Status {}: {}",
                status, body
            )));
        }

        response
            .json::<StatusResult>()
            .await
            .map(|mut result| {
                // Ensure registered is true for successful responses
                result.registered = true;
                if result.agent_id.is_empty() {
                    result.agent_id = agent_id;
                }
                result
            })
            .map_err(|e| HaiError::InvalidResponse(e.to_string()))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let client = HaiClient::new("https://api.hai.ai")
            .with_api_key("test-key");

        assert_eq!(client.endpoint, "https://api.hai.ai");
        assert_eq!(client.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_endpoint_normalization() {
        let client = HaiClient::new("https://api.hai.ai/");
        assert_eq!(client.endpoint, "https://api.hai.ai");
    }

    #[test]
    fn test_error_display() {
        let err = HaiError::ConnectionFailed("timeout".to_string());
        assert_eq!(format!("{}", err), "Connection failed: timeout");

        let err = HaiError::AuthRequired;
        assert_eq!(
            format!("{}", err),
            "Authentication required: provide an API key"
        );
    }

    #[test]
    fn test_registration_result_serialization() {
        let result = RegistrationResult {
            agent_id: "agent-123".to_string(),
            jacs_id: "jacs-456".to_string(),
            dns_verified: true,
            signatures: vec![HaiSignature {
                key_id: "key-1".to_string(),
                algorithm: "Ed25519".to_string(),
                signature: "c2lnbmF0dXJl".to_string(),
                signed_at: "2024-01-15T10:30:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: RegistrationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.agent_id, "agent-123");
        assert_eq!(parsed.signatures.len(), 1);
    }

    #[test]
    fn test_status_result_serialization() {
        let result = StatusResult {
            registered: true,
            agent_id: "agent-123".to_string(),
            registration_id: "reg-456".to_string(),
            registered_at: "2024-01-15T10:30:00Z".to_string(),
            hai_signatures: vec!["sig-1".to_string(), "sig-2".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: StatusResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.registered, true);
        assert_eq!(parsed.agent_id, "agent-123");
        assert_eq!(parsed.registration_id, "reg-456");
        assert_eq!(parsed.hai_signatures.len(), 2);
    }

    #[test]
    fn test_status_result_not_registered() {
        let result = StatusResult {
            registered: false,
            agent_id: "agent-123".to_string(),
            registration_id: String::new(),
            registered_at: String::new(),
            hai_signatures: Vec::new(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: StatusResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.registered, false);
        assert_eq!(parsed.agent_id, "agent-123");
        assert!(parsed.registration_id.is_empty());
    }
}
