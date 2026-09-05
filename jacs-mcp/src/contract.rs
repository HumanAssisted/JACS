use crate::jacs_tools::JacsMcpServer;
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

    // The contract is an inventory, not an authority-bearing runtime profile.
    // Generate its prose directly from the full compiled list so no unsafe
    // `full` process profile needs to exist merely for documentation.
    let tool_names = tools
        .iter()
        .map(|tool| format!("- {}", tool.name))
        .collect::<Vec<_>>()
        .join("\n");

    JacsMcpContractSnapshot {
        schema_version: 1,
        server: JacsMcpServerMetadata {
            name: "jacs-mcp".into(),
            title: Some("JACS MCP Server".into()),
            version: env!("CARGO_PKG_VERSION").into(),
            website_url: Some("https://humanassisted.github.io/JACS/".into()),
            instructions: Some(format!(
                "JACS MCP compiled contract inventory contains {} tools. Runtime defaults to verification-only and advertises only its active subset.\n\nCompiled tools:\n{}",
                tools.len(), tool_names
            )),
        },
        tools,
    }
}
