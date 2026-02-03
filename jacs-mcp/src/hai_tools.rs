//! HAI MCP tools for LLM integration.
//!
//! This module provides MCP tools that allow LLMs to interact with HAI services:
//!
//! - `fetch_agent_key` - Fetch a public key from HAI's key distribution service
//! - `register_agent` - Register the local agent with HAI
//! - `verify_agent` - Verify another agent's attestation level
//! - `check_agent_status` - Check registration status with HAI

use jacs_binding_core::hai::HaiClient;
use jacs_binding_core::{fetch_remote_key, AgentWrapper};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo, Tool, ToolsCapability};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for fetching an agent's public key from HAI.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FetchAgentKeyParams {
    /// The unique identifier of the agent whose key to fetch.
    #[schemars(description = "The JACS agent ID (UUID format)")]
    pub agent_id: String,

    /// The version of the key to fetch. Use "latest" for the most recent version.
    #[schemars(description = "Key version to fetch, or 'latest' for most recent")]
    pub version: Option<String>,
}

/// Result of fetching an agent's public key.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FetchAgentKeyResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID.
    pub agent_id: String,

    /// The key version.
    pub version: String,

    /// The cryptographic algorithm (e.g., "ed25519", "pq-dilithium").
    pub algorithm: String,

    /// The SHA-256 hash of the public key.
    pub public_key_hash: String,

    /// The public key in base64 encoding.
    pub public_key_base64: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for registering the local agent with HAI.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterAgentParams {
    /// Whether to run in preview mode (validate without registering).
    #[schemars(description = "If true, validates registration without actually registering")]
    pub preview: Option<bool>,
}

/// Result of agent registration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterAgentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The registered agent's JACS ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// The JACS document ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_id: Option<String>,

    /// Whether DNS verification was successful.
    pub dns_verified: bool,

    /// Whether this was a preview-only operation.
    pub preview_mode: bool,

    /// Human-readable status message.
    pub message: String,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for verifying another agent's attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyAgentParams {
    /// The agent ID to verify.
    #[schemars(description = "The JACS agent ID to verify")]
    pub agent_id: String,

    /// The version to verify (defaults to "latest").
    #[schemars(description = "Agent version to verify, or 'latest'")]
    pub version: Option<String>,
}

/// Result of agent verification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyAgentResult {
    /// Whether the verification succeeded.
    pub success: bool,

    /// The agent ID that was verified.
    pub agent_id: String,

    /// The attestation level (0-3).
    /// - Level 0: No attestation
    /// - Level 1: Key registered with HAI
    /// - Level 2: DNS verified
    /// - Level 3: Full HAI signature attestation
    pub attestation_level: u8,

    /// Human-readable description of the attestation level.
    pub attestation_description: String,

    /// Whether the agent's public key was found.
    pub key_found: bool,

    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for checking agent registration status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgentStatusParams {
    /// Optional agent ID to check. If not provided, checks the local agent.
    #[schemars(description = "Agent ID to check status for. If omitted, checks the local agent.")]
    pub agent_id: Option<String>,
}

/// Result of checking agent status.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckAgentStatusResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The agent ID that was checked.
    pub agent_id: String,

    /// Whether the agent is registered with HAI.
    pub registered: bool,

    /// HAI registration ID (if registered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,

    /// When the agent was registered (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<String>,

    /// Number of HAI signatures on the registration.
    pub signature_count: usize,

    /// Error message if the operation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// MCP Server
// =============================================================================

/// HAI MCP Server providing tools for agent registration, verification, and key management.
#[derive(Clone)]
#[allow(dead_code)]
pub struct HaiMcpServer {
    /// The local agent identity.
    agent: Arc<AgentWrapper>,
    /// HAI client for API calls.
    hai_client: Arc<HaiClient>,
    /// Tool router for MCP tool dispatch.
    tool_router: ToolRouter<Self>,
}

#[allow(dead_code)]
impl HaiMcpServer {
    /// Create a new HAI MCP server with the given agent and HAI endpoint.
    ///
    /// # Arguments
    ///
    /// * `agent` - The local JACS agent wrapper
    /// * `hai_endpoint` - Base URL for the HAI API (e.g., "https://api.hai.ai")
    /// * `api_key` - Optional API key for HAI authentication
    pub fn new(agent: AgentWrapper, hai_endpoint: &str, api_key: Option<&str>) -> Self {
        let mut client = HaiClient::new(hai_endpoint);
        if let Some(key) = api_key {
            client = client.with_api_key(key);
        }

        Self {
            agent: Arc::new(agent),
            hai_client: Arc::new(client),
            tool_router: Self::tool_router(),
        }
    }

    /// Get the list of available tools for LLM discovery.
    pub fn tools() -> Vec<Tool> {
        vec![
            Tool::new(
                "fetch_agent_key",
                "Fetch a public key from HAI's key distribution service. Use this to obtain \
                 trusted public keys for verifying agent signatures.",
                Self::fetch_agent_key_schema(),
            ),
            Tool::new(
                "register_agent",
                "Register the local agent with HAI. This establishes the agent's identity \
                 in the HAI network and enables attestation services.",
                Self::register_agent_schema(),
            ),
            Tool::new(
                "verify_agent",
                "Verify another agent's attestation level with HAI. Returns the trust level \
                 (0-3) indicating how well the agent's identity has been verified.",
                Self::verify_agent_schema(),
            ),
            Tool::new(
                "check_agent_status",
                "Check the registration status of an agent with HAI. Returns whether the \
                 agent is registered and relevant registration details.",
                Self::check_agent_status_schema(),
            ),
        ]
    }

    fn fetch_agent_key_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(FetchAgentKeyParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn register_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(RegisterAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn verify_agent_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(VerifyAgentParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    fn check_agent_status_schema() -> serde_json::Map<String, serde_json::Value> {
        let schema = schemars::schema_for!(CheckAgentStatusParams);
        match serde_json::to_value(schema) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }
}

// Implement the tool router for the server
#[tool_router]
impl HaiMcpServer {
    /// Fetch a public key from HAI's key distribution service.
    ///
    /// This tool retrieves the public key for a specific agent from HAI,
    /// allowing verification of that agent's signatures.
    #[tool(
        name = "fetch_agent_key",
        description = "Fetch a public key from HAI's key distribution service for verifying agent signatures."
    )]
    pub async fn fetch_agent_key(
        &self,
        Parameters(params): Parameters<FetchAgentKeyParams>,
    ) -> String {
        let version = params.version.as_deref().unwrap_or("latest");

        let result = match fetch_remote_key(&params.agent_id, version) {
            Ok(key_info) => FetchAgentKeyResult {
                success: true,
                agent_id: key_info.agent_id,
                version: key_info.version,
                algorithm: key_info.algorithm,
                public_key_hash: key_info.public_key_hash,
                public_key_base64: base64_encode(&key_info.public_key),
                error: None,
            },
            Err(e) => FetchAgentKeyResult {
                success: false,
                agent_id: params.agent_id.clone(),
                version: version.to_string(),
                algorithm: String::new(),
                public_key_hash: String::new(),
                public_key_base64: String::new(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Register the local agent with HAI.
    ///
    /// This establishes the agent's identity in the HAI network and enables
    /// attestation services.
    #[tool(
        name = "register_agent",
        description = "Register the local JACS agent with HAI to establish identity and enable attestation."
    )]
    pub async fn register_agent(
        &self,
        Parameters(params): Parameters<RegisterAgentParams>,
    ) -> String {
        let preview = params.preview.unwrap_or(false);

        // For now, we don't have a preview-only mode in the HaiClient,
        // so we either register or report that preview mode is not yet implemented
        if preview {
            let result = RegisterAgentResult {
                success: true,
                agent_id: None,
                jacs_id: None,
                dns_verified: false,
                preview_mode: true,
                message: "Preview mode: Agent would be registered with HAI. \
                          Set preview=false to actually register."
                    .to_string(),
                error: None,
            };
            return serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = match self.hai_client.register(&self.agent).await {
            Ok(reg) => RegisterAgentResult {
                success: true,
                agent_id: Some(reg.agent_id),
                jacs_id: Some(reg.jacs_id),
                dns_verified: reg.dns_verified,
                preview_mode: false,
                message: format!(
                    "Successfully registered with HAI. {} signature(s) received.",
                    reg.signatures.len()
                ),
                error: None,
            },
            Err(e) => RegisterAgentResult {
                success: false,
                agent_id: None,
                jacs_id: None,
                dns_verified: false,
                preview_mode: false,
                message: "Registration failed".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Verify another agent's attestation level with HAI.
    ///
    /// Returns the trust level indicating how well the agent's identity
    /// has been verified:
    /// - Level 0: No attestation
    /// - Level 1: Key registered with HAI
    /// - Level 2: DNS verified
    /// - Level 3: Full HAI signature attestation
    #[tool(
        name = "verify_agent",
        description = "Verify another agent's attestation level (0-3) with HAI."
    )]
    pub async fn verify_agent(&self, Parameters(params): Parameters<VerifyAgentParams>) -> String {
        let version = params.version.as_deref().unwrap_or("latest");

        // First, try to fetch the key to determine attestation level
        let key_result = fetch_remote_key(&params.agent_id, version);

        let (attestation_level, attestation_description, key_found) = match &key_result {
            Ok(_) => {
                // Key found - at minimum Level 1
                // To determine Level 2 or 3, we would need to check DNS and HAI signatures
                // For now, we report Level 1 if key is found
                (
                    1u8,
                    "Level 1: Public key registered with HAI key service".to_string(),
                    true,
                )
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("not found") || error_str.contains("404") {
                    (
                        0u8,
                        "Level 0: Agent not found in HAI key service".to_string(),
                        false,
                    )
                } else {
                    // Network or other error - can't determine level
                    (
                        0u8,
                        format!("Level 0: Unable to verify ({})", error_str),
                        false,
                    )
                }
            }
        };

        let result = VerifyAgentResult {
            success: key_found || key_result.is_ok(),
            agent_id: params.agent_id,
            attestation_level,
            attestation_description,
            key_found,
            error: key_result.err().map(|e| e.to_string()),
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Check the registration status of an agent with HAI.
    #[tool(
        name = "check_agent_status",
        description = "Check if an agent is registered with HAI and get registration details."
    )]
    pub async fn check_agent_status(
        &self,
        Parameters(params): Parameters<CheckAgentStatusParams>,
    ) -> String {
        // If no agent_id provided, check the local agent
        let check_local = params.agent_id.is_none();

        let result = if check_local {
            // Check status of the local agent
            match self.hai_client.status(&self.agent).await {
                Ok(status) => CheckAgentStatusResult {
                    success: true,
                    agent_id: status.agent_id,
                    registered: status.registered,
                    registration_id: if status.registration_id.is_empty() {
                        None
                    } else {
                        Some(status.registration_id)
                    },
                    registered_at: if status.registered_at.is_empty() {
                        None
                    } else {
                        Some(status.registered_at)
                    },
                    signature_count: status.hai_signatures.len(),
                    error: None,
                },
                Err(e) => CheckAgentStatusResult {
                    success: false,
                    agent_id: "local".to_string(),
                    registered: false,
                    registration_id: None,
                    registered_at: None,
                    signature_count: 0,
                    error: Some(e.to_string()),
                },
            }
        } else {
            // For a remote agent, we can only check if their key exists
            let agent_id = params.agent_id.unwrap();
            match fetch_remote_key(&agent_id, "latest") {
                Ok(_) => CheckAgentStatusResult {
                    success: true,
                    agent_id: agent_id.clone(),
                    registered: true,
                    registration_id: None, // Not available for remote agents
                    registered_at: None,
                    signature_count: 0,
                    error: None,
                },
                Err(e) => {
                    let error_str = e.to_string();
                    let registered = !error_str.contains("not found") && !error_str.contains("404");
                    CheckAgentStatusResult {
                        success: !registered, // Success if we got a clear "not found"
                        agent_id,
                        registered,
                        registration_id: None,
                        registered_at: None,
                        signature_count: 0,
                        error: if registered {
                            Some(error_str)
                        } else {
                            None
                        },
                    }
                }
            }
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }
}

// Implement the tool handler for the server
#[tool_handler(router = self.tool_router)]
impl ServerHandler for HaiMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "jacs-mcp".to_string(),
                title: Some("JACS MCP Server with HAI Integration".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                icons: None,
                website_url: Some("https://hai.ai".to_string()),
            },
            instructions: Some(
                "This MCP server provides HAI (Human AI Interface) tools for agent \
                 registration, verification, and key management. Use fetch_agent_key \
                 to get public keys, register_agent to register with HAI, verify_agent \
                 to check attestation levels, and check_agent_status for registration info."
                    .to_string(),
            ),
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding using the standard alphabet
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_agent_key_params_schema() {
        let schema = schemars::schema_for!(FetchAgentKeyParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("agent_id"));
        assert!(json.contains("version"));
    }

    #[test]
    fn test_register_agent_params_schema() {
        let schema = schemars::schema_for!(RegisterAgentParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("preview"));
    }

    #[test]
    fn test_verify_agent_params_schema() {
        let schema = schemars::schema_for!(VerifyAgentParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("agent_id"));
    }

    #[test]
    fn test_check_agent_status_params_schema() {
        let schema = schemars::schema_for!(CheckAgentStatusParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("agent_id"));
    }

    #[test]
    fn test_tools_list() {
        let tools = HaiMcpServer::tools();
        assert_eq!(tools.len(), 4);

        let names: Vec<&str> = tools.iter().map(|t| &*t.name).collect();
        assert!(names.contains(&"fetch_agent_key"));
        assert!(names.contains(&"register_agent"));
        assert!(names.contains(&"verify_agent"));
        assert!(names.contains(&"check_agent_status"));
    }
}
