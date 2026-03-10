use crate::jacs_tools::JacsMcpServer;
use jacs_binding_core::AgentWrapper;
use rmcp::ServerHandler;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Machine-readable snapshot of the canonical Rust MCP contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JacsMcpContractSnapshot {
    pub schema_version: u32,
    pub server: JacsMcpServerMetadata,
    pub tools: Vec<JacsMcpToolContract>,
}

/// Stable server metadata exported for downstream adapter drift tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JacsMcpServerMetadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// Stable per-tool metadata exported from the canonical Rust server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JacsMcpToolContract {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

/// Export the canonical Rust MCP contract for documentation and drift tests.
pub fn canonical_contract_snapshot() -> JacsMcpContractSnapshot {
    let mut tools: Vec<JacsMcpToolContract> = JacsMcpServer::tools()
        .into_iter()
        .map(|tool| JacsMcpToolContract {
            name: tool.name.to_string(),
            title: tool.title.clone(),
            description: tool
                .description
                .as_ref()
                .map(|description| description.to_string()),
            input_schema: tool.schema_as_json_value(),
            output_schema: tool
                .output_schema
                .map(|schema| Value::Object(schema.as_ref().clone())),
        })
        .collect();

    tools.sort_by(|left, right| left.name.cmp(&right.name));

    let info = JacsMcpServer::new(AgentWrapper::new()).get_info();

    JacsMcpContractSnapshot {
        schema_version: 1,
        server: JacsMcpServerMetadata {
            name: info.server_info.name,
            title: info.server_info.title,
            version: info.server_info.version,
            website_url: info.server_info.website_url,
            instructions: info.instructions,
        },
        tools,
    }
}
