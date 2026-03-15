//! JACS MCP tools for data provenance and cryptographic signing.
//!
//! This module provides MCP tools for agent state signing, verification,
//! messaging, agreements, A2A interoperability, and trust store management.
//!
//! ## Tech Debt (Issue 017)
//!
//! This file contains all 42 tool handler implementations in a single 4400+
//! line monolith. TASK_038 split **type definitions and tool registration**
//! into per-family modules under `tools/`, but the actual handler methods
//! remain here.
//!
//! A future refactoring should move handler methods into their respective
//! `tools/*.rs` modules (e.g., `tools::memory::handle_memory_save()`),
//! leaving only the `JacsMcpServer` struct, `ServerHandler` impl, and
//! shared helper functions in this file. This will require either:
//! - A facade pattern where `jacs_tools.rs` delegates to module functions, or
//! - Adjusting the `#[tool_router]` / `#[tool_handler]` macros from rmcp
//!   to support handlers spread across multiple modules.

use jacs::document::DocumentService;
use jacs::schema::agentstate_crud;
use jacs::validation::require_relative_path_safe;
use jacs_binding_core::AgentWrapper;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo, Tool, ToolsCapability};
use rmcp::{ServerHandler, tool, tool_router};
use sha2::{Digest, Sha256};

use crate::tools::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

// =============================================================================
// Helper Functions
// =============================================================================

/// Validates that a string is a valid UUID format.
/// Returns an error message if invalid, None if valid.
fn validate_agent_id(agent_id: &str) -> Result<(), String> {
    if agent_id.is_empty() {
        return Err("agent_id cannot be empty".to_string());
    }

    // Try parsing as UUID
    match Uuid::parse_str(agent_id) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!(
            "Invalid agent_id format '{}'. Expected UUID format (e.g., '550e8400-e29b-41d4-a716-446655440000')",
            agent_id
        )),
    }
}

/// Check if registration is allowed via environment variable.
/// Registration requires explicit opt-in for security.
fn is_registration_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_REGISTRATION")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

/// Check if untrusting agents is allowed via environment variable.
/// Untrusting requires explicit opt-in to prevent prompt injection attacks
/// from removing trusted agents without user consent.
fn is_untrust_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_UNTRUST")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

fn inline_secrets_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_INLINE_SECRETS")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

fn arbitrary_state_files_allowed() -> bool {
    std::env::var("JACS_MCP_ALLOW_ARBITRARY_STATE_FILES")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

fn configured_state_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(root) = std::env::var("JACS_DATA_DIRECTORY")
        && !root.trim().is_empty()
    {
        roots.push(PathBuf::from(root));
    }

    roots.push(PathBuf::from("jacs_data"));
    roots
}

fn absolute_from_cwd(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn validate_state_file_root(file_path: &str) -> Result<(), String> {
    if arbitrary_state_files_allowed() {
        return Ok(());
    }

    let cwd = std::env::current_dir()
        .map_err(|e| format!("Failed to determine working directory: {}", e))?;
    let requested = absolute_from_cwd(Path::new(file_path), &cwd);
    let allowed_roots = configured_state_roots();

    let lexically_allowed = allowed_roots.iter().any(|root| {
        let root_abs = absolute_from_cwd(root, &cwd);
        requested.starts_with(&root_abs)
    });

    if !lexically_allowed {
        return Err("STATE_FILE_ACCESS_BLOCKED".to_string());
    }

    if requested.exists() {
        let canonical_requested = requested
            .canonicalize()
            .map_err(|_| "STATE_FILE_ACCESS_BLOCKED".to_string())?;
        let canonically_allowed = allowed_roots.iter().any(|root| {
            let root_abs = absolute_from_cwd(root, &cwd);
            let canonical_root = root_abs.canonicalize().unwrap_or(root_abs);
            canonical_requested.starts_with(&canonical_root)
        });

        if !canonically_allowed {
            return Err("STATE_FILE_ACCESS_BLOCKED".to_string());
        }
    }

    Ok(())
}

fn validate_optional_relative_path(label: &str, path: Option<&String>) -> Result<(), String> {
    if let Some(path) = path {
        require_relative_path_safe(path)
            .map_err(|e| format!("{} path validation failed: {}", label, e))?;
    }
    Ok(())
}

/// Build a stable storage lookup key (`jacsId:jacsVersion`) from a signed document.
fn extract_document_lookup_key(doc: &serde_json::Value) -> Option<String> {
    let id = doc
        .get("jacsId")
        .or_else(|| doc.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let version = doc
        .get("jacsVersion")
        .or_else(|| doc.get("version"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    match (id, version) {
        (Some(i), Some(v)) => Some(format!("{}:{}", i, v)),
        (Some(i), None) => Some(i.to_string()),
        _ => None,
    }
}

/// Parse a signed document JSON string and return its stable lookup key.
fn extract_document_lookup_key_from_str(document_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(document_json)
        .ok()
        .and_then(|v| extract_document_lookup_key(&v))
}

/// Pull embedded state content from a signed agent-state document.
fn extract_embedded_state_content(doc: &serde_json::Value) -> Option<String> {
    doc.get("jacsAgentStateContent")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            doc.get("jacsFiles")
                .and_then(|v| v.as_array())
                .and_then(|files| files.first())
                .and_then(|file| file.get("contents"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
}

/// Update embedded state content and keep per-file content hashes in sync.
fn update_embedded_state_content(doc: &mut serde_json::Value, new_content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(new_content.as_bytes());
    let new_hash = format!("{:x}", hasher.finalize());

    doc["jacsAgentStateContent"] = serde_json::json!(new_content);

    if let Some(files) = doc.get_mut("jacsFiles").and_then(|v| v.as_array_mut()) {
        for file in files {
            if let Some(obj) = file.as_object_mut() {
                obj.insert("embed".to_string(), serde_json::json!(true));
                obj.insert("contents".to_string(), serde_json::json!(new_content));
                obj.insert("sha256".to_string(), serde_json::json!(new_hash.clone()));
            }
        }
    }

    new_hash
}

fn value_string(doc: &serde_json::Value, field: &str) -> Option<String> {
    doc.get(field).and_then(|v| v.as_str()).map(str::to_string)
}

fn value_string_vec(doc: &serde_json::Value, field: &str) -> Option<Vec<String>> {
    doc.get(field).and_then(|v| v.as_array()).map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect::<Vec<_>>()
    })
}

/// Extract verification validity from `verify_a2a_artifact` details JSON.
/// Defaults to `false` on malformed/missing fields to avoid optimistic trust.
fn extract_verify_a2a_valid(details_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(details_json)
        .ok()
        .and_then(|v| v.get("valid").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// Format a SystemTime as an ISO 8601 UTC timestamp string.
fn format_iso8601(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    // Simple conversion: seconds -> year/month/day/hour/min/sec
    // Using a basic algorithm that handles dates from 1970 onwards
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = is_leap(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        remaining + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// =============================================================================
// MCP Server
// =============================================================================

/// JACS MCP Server providing tools for data provenance, cryptographic signing,
/// messaging, agreements, A2A interoperability, and trust store management.
#[derive(Clone)]
#[allow(dead_code)]
pub struct JacsMcpServer {
    /// The local agent identity.
    agent: Arc<AgentWrapper>,
    /// Unified document service resolved from the loaded agent config.
    document_service: Option<Arc<dyn DocumentService>>,
    /// Tool router for MCP tool dispatch.
    tool_router: ToolRouter<Self>,
    /// Whether agent creation is allowed (from JACS_MCP_ALLOW_REGISTRATION env var).
    registration_allowed: bool,
    /// Whether untrusting agents is allowed (from JACS_MCP_ALLOW_UNTRUST env var).
    untrust_allowed: bool,
    /// Runtime tool profile controlling which tools are registered.
    profile: crate::profile::Profile,
}

#[allow(dead_code)]
impl JacsMcpServer {
    /// Create a new JACS MCP server with the given agent and default profile.
    ///
    /// The runtime profile is resolved from `JACS_MCP_PROFILE` env var,
    /// defaulting to `Core`.
    ///
    /// # Arguments
    ///
    /// * `agent` - The local JACS agent wrapper
    ///
    /// # Environment Variables
    ///
    /// * `JACS_MCP_ALLOW_REGISTRATION` - Set to "true" to enable the jacs_create_agent tool
    /// * `JACS_MCP_ALLOW_UNTRUST` - Set to "true" to enable the jacs_untrust_agent tool
    /// * `JACS_MCP_PROFILE` - Set to "full" to expose all tools, defaults to "core"
    pub fn new(agent: AgentWrapper) -> Self {
        let profile = crate::profile::Profile::resolve(None);
        Self::with_profile(agent, profile)
    }

    /// Create a new JACS MCP server with an explicit runtime profile.
    ///
    /// Use this when the profile has been parsed from a CLI flag.
    pub fn with_profile(agent: AgentWrapper, profile: crate::profile::Profile) -> Self {
        let registration_allowed = is_registration_allowed();
        let untrust_allowed = is_untrust_allowed();
        let document_service = match jacs::document::service_from_agent(agent.inner_arc()) {
            Ok(service) => Some(service),
            Err(err) => {
                tracing::warn!("Document service unavailable for MCP server: {}", err);
                None
            }
        };

        if registration_allowed {
            tracing::info!("Agent creation is ENABLED (JACS_MCP_ALLOW_REGISTRATION=true)");
        } else {
            tracing::info!(
                "Agent creation is DISABLED. Set JACS_MCP_ALLOW_REGISTRATION=true to enable."
            );
        }

        tracing::info!(profile = %profile, "Tool profile active");

        Self {
            agent: Arc::new(agent),
            document_service,
            tool_router: Self::tool_router(),
            registration_allowed,
            untrust_allowed,
            profile,
        }
    }

    /// Get the list of all compiled-in tools (ignores runtime profile).
    ///
    /// Use this for contract snapshots and tests that need the full surface.
    pub fn tools() -> Vec<Tool> {
        crate::tools::all_tools()
    }

    /// Get the list of tools for the active runtime profile.
    ///
    /// This is what should be advertised to MCP clients.
    pub fn active_tools(&self) -> Vec<Tool> {
        self.profile.tools()
    }

    /// Get a reference to the active runtime profile.
    pub fn profile(&self) -> &crate::profile::Profile {
        &self.profile
    }
}

// Implement the tool router for the server
#[tool_router]
impl JacsMcpServer {
    /// Sign an agent state file to create a cryptographically signed JACS document.
    ///
    /// Reads the file, creates an agent state document with metadata, and signs it
    /// using the local agent's keys. For hooks, content is always embedded.
    #[tool(
        name = "jacs_sign_state",
        description = "Sign an agent state file (memory/skill/plan/config/hook) to create a signed JACS document."
    )]
    pub async fn jacs_sign_state(&self, Parameters(params): Parameters<SignStateParams>) -> String {
        // Security: Validate file_path to prevent path traversal attacks via prompt injection.
        if let Err(e) = require_relative_path_safe(&params.file_path) {
            let result = SignStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Path validation failed".to_string(),
                error: Some(format!("PATH_TRAVERSAL_BLOCKED: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if let Err(error_code) = validate_state_file_root(&params.file_path) {
            let result = SignStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "State file access is restricted to approved JACS data roots.".to_string(),
                error: Some(error_code),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Always embed state content for MCP-originated state documents so follow-up
        // reads/updates can operate purely on JACS documents without direct file I/O.
        let embed = params.embed.unwrap_or(true);

        // Create the agent state document with file reference
        let mut doc = match agentstate_crud::create_agentstate_with_file(
            &params.state_type,
            &params.name,
            &params.file_path,
            embed,
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = SignStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to create agent state document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Set optional fields
        if let Some(desc) = &params.description {
            doc["jacsAgentStateDescription"] = serde_json::json!(desc);
        }

        if let Some(framework) = &params.framework {
            if let Err(e) = agentstate_crud::set_agentstate_framework(&mut doc, framework) {
                let result = SignStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to set framework".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        if let Some(tags) = &params.tags {
            let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
            if let Err(e) = agentstate_crud::set_agentstate_tags(&mut doc, tag_refs) {
                let result = SignStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to set tags".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // Set origin as "authored" for directly signed state
        let _ = agentstate_crud::set_agentstate_origin(&mut doc, "authored", None);

        // Sign and persist through JACS document storage so subsequent MCP calls can
        // reference only the JACS document ID (no sidecar/path coupling).
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            Some(embed || params.state_type == "hook"),
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&SignStateResult {
                            success: false,
                            jacs_document_id: None,
                            state_type: params.state_type,
                            name: params.name,
                            message: "Failed to determine the signed document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&SignStateResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        state_type: params.state_type,
                        name: params.name,
                        message: "Failed to persist signed state document".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

                SignStateResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    state_type: params.state_type,
                    name: params.name,
                    message: format!(
                        "Successfully signed agent state file '{}'",
                        params.file_path
                    ),
                    error: None,
                }
            }
            Err(e) => SignStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Failed to sign document".to_string(),
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Verify the integrity and authenticity of a signed agent state.
    ///
    /// Checks both the file content hash against the signed hash and verifies
    /// the cryptographic signature on the document.
    #[tool(
        name = "jacs_verify_state",
        description = "Verify a signed agent state's file hash and cryptographic signature."
    )]
    pub async fn jacs_verify_state(
        &self,
        Parameters(params): Parameters<VerifyStateParams>,
    ) -> String {
        // MCP policy: verification must resolve through JACS documents, not direct file paths.
        if params.jacs_id.is_none() && params.file_path.is_none() {
            let result = VerifyStateResult {
                success: false,
                hash_match: false,
                signature_valid: false,
                signing_info: None,
                message: "Missing state reference. Provide jacs_id (uuid:version).".to_string(),
                error: Some("MISSING_PARAMETER".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if params.jacs_id.is_none() {
            let result = VerifyStateResult {
                success: false,
                hash_match: false,
                signature_valid: false,
                signing_info: None,
                message: "file_path-based verification is disabled in MCP. Use jacs_id."
                    .to_string(),
                error: Some("FILESYSTEM_ACCESS_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let jacs_id = params.jacs_id.as_deref().unwrap_or_default();
        let doc_string = match self.agent.get_document_by_id(jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = VerifyStateResult {
                    success: false,
                    hash_match: false,
                    signature_valid: false,
                    signing_info: None,
                    message: format!("Failed to load document '{}'", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        match self.agent.verify_document(&doc_string) {
            Ok(valid) => {
                let signing_info = serde_json::from_str::<serde_json::Value>(&doc_string)
                    .ok()
                    .and_then(|doc| doc.get("jacsSignature").cloned())
                    .map(|sig| sig.to_string());

                let result = VerifyStateResult {
                    success: true,
                    hash_match: valid,
                    signature_valid: valid,
                    signing_info,
                    message: if valid {
                        format!("Document '{}' verified successfully", jacs_id)
                    } else {
                        format!("Document '{}' signature verification failed", jacs_id)
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = VerifyStateResult {
                    success: false,
                    hash_match: false,
                    signature_valid: false,
                    signing_info: None,
                    message: format!("Failed to verify document '{}': {}", jacs_id, e),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Load a signed agent state document and optionally verify it.
    ///
    /// Returns the content of the state along with verification status.
    #[tool(
        name = "jacs_load_state",
        description = "Load a signed agent state document, optionally verifying before returning content."
    )]
    pub async fn jacs_load_state(&self, Parameters(params): Parameters<LoadStateParams>) -> String {
        if params.file_path.is_some() && params.jacs_id.is_none() {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: None,
                message: "file_path-based loading is disabled in MCP. Use jacs_id.".to_string(),
                error: Some("FILESYSTEM_ACCESS_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if params.jacs_id.is_none() {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: None,
                message: "Missing state reference. Provide jacs_id (uuid:version).".to_string(),
                error: Some("MISSING_PARAMETER".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let require_verified = params.require_verified.unwrap_or(true);
        let jacs_id = params.jacs_id.as_deref().unwrap_or_default();
        let mut warnings = Vec::new();
        let mut verified = false;

        let doc_string = match self.agent.get_document_by_id(jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = LoadStateResult {
                    success: false,
                    content: None,
                    verified,
                    warnings: if warnings.is_empty() {
                        None
                    } else {
                        Some(warnings)
                    },
                    message: format!("Failed to load state document '{}'", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        if require_verified {
            match self.agent.verify_document(&doc_string) {
                Ok(true) => {
                    verified = true;
                }
                Ok(false) => {
                    warnings.push("Document signature verification failed.".to_string());
                }
                Err(e) => {
                    warnings.push(format!("Could not verify document signature: {}", e));
                }
            }
        }

        if require_verified && !verified {
            let result = LoadStateResult {
                success: false,
                content: None,
                verified: false,
                warnings: if warnings.is_empty() {
                    None
                } else {
                    Some(warnings)
                },
                message: "Verification required but the state document could not be verified."
                    .to_string(),
                error: Some("VERIFICATION_FAILED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
            Ok(v) => v,
            Err(e) => {
                let result = LoadStateResult {
                    success: false,
                    content: None,
                    verified,
                    warnings: if warnings.is_empty() {
                        None
                    } else {
                        Some(warnings)
                    },
                    message: format!("State document '{}' is not valid JSON", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let content = extract_embedded_state_content(&doc);
        if content.is_none() {
            warnings.push(
                "State document does not contain embedded content. Re-sign with embed=true."
                    .to_string(),
            );
        }

        let result = LoadStateResult {
            success: true,
            content,
            verified,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
            message: if require_verified && verified {
                format!("Successfully loaded and verified '{}'", jacs_id)
            } else {
                format!("Loaded '{}' from JACS storage", jacs_id)
            },
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, Some(&doc))
    }

    /// Update a previously signed agent state file.
    ///
    /// If new_content is provided, writes it to the file first. Then recomputes
    /// the SHA-256 hash and creates a new signed version of the document.
    #[tool(
        name = "jacs_update_state",
        description = "Update a previously signed agent state document by jacs_id with new embedded content and re-sign."
    )]
    pub async fn jacs_update_state(
        &self,
        Parameters(params): Parameters<UpdateStateParams>,
    ) -> String {
        let jacs_id = match params.jacs_id.as_deref() {
            Some(id) => id,
            None => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: "file_path-based updates are disabled in MCP. Provide jacs_id."
                        .to_string(),
                    error: Some("FILESYSTEM_ACCESS_DISABLED".to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let existing_doc_string = match self.agent.get_document_by_id(jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: format!("Failed to load state document '{}'", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut doc = match serde_json::from_str::<serde_json::Value>(&existing_doc_string) {
            Ok(v) => v,
            Err(e) => {
                let result = UpdateStateResult {
                    success: false,
                    jacs_document_version_id: None,
                    new_hash: None,
                    message: format!("State document '{}' is not valid JSON", jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let new_hash = params
            .new_content
            .as_deref()
            .map(|content| update_embedded_state_content(&mut doc, content));

        let updated_doc_string =
            match self
                .agent
                .update_document(jacs_id, &doc.to_string(), None, None)
            {
                Ok(doc) => doc,
                Err(e) => {
                    let result = UpdateStateResult {
                        success: false,
                        jacs_document_version_id: None,
                        new_hash,
                        message: format!("Failed to update and re-sign '{}'", jacs_id),
                        error: Some(e.to_string()),
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
            };

        let version_id = serde_json::from_str::<serde_json::Value>(&updated_doc_string)
            .ok()
            .and_then(|v| extract_document_lookup_key(&v))
            .unwrap_or_else(|| "unknown".to_string());

        let result = UpdateStateResult {
            success: true,
            jacs_document_version_id: Some(version_id),
            new_hash,
            message: format!("Successfully updated and re-signed '{}'", jacs_id),
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// List signed agent state documents.
    #[tool(
        name = "jacs_list_state",
        description = "List signed agent state documents, with optional filtering."
    )]
    pub async fn jacs_list_state(&self, Parameters(params): Parameters<ListStateParams>) -> String {
        let keys = match self.agent.list_document_keys() {
            Ok(keys) => keys,
            Err(e) => {
                let result = ListStateResult {
                    success: false,
                    documents: Vec::new(),
                    message: "Failed to enumerate stored documents".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut matched = Vec::new();

        for key in keys {
            let doc_string = match self.agent.get_document_by_id(&key) {
                Ok(doc) => doc,
                Err(_) => continue,
            };
            let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
                Ok(doc) => doc,
                Err(_) => continue,
            };

            if doc.get("jacsType").and_then(|v| v.as_str()) != Some("agentstate") {
                continue;
            }

            let state_type = value_string(&doc, "jacsAgentStateType").unwrap_or_default();
            if let Some(filter) = params.state_type.as_deref()
                && state_type != filter
            {
                continue;
            }

            let framework = value_string(&doc, "jacsAgentStateFramework");
            if let Some(filter) = params.framework.as_deref()
                && framework.as_deref() != Some(filter)
            {
                continue;
            }

            let tags = value_string_vec(&doc, "jacsAgentStateTags");
            if let Some(filter_tags) = params.tags.as_ref() {
                let doc_tags = tags.clone().unwrap_or_default();
                if !filter_tags
                    .iter()
                    .all(|tag| doc_tags.iter().any(|item| item == tag))
                {
                    continue;
                }
            }

            let name = value_string(&doc, "jacsAgentStateName").unwrap_or_else(|| key.clone());
            let version_date = value_string(&doc, "jacsVersionDate").unwrap_or_default();

            matched.push((
                version_date,
                key.clone(),
                StateListEntry {
                    jacs_document_id: key,
                    state_type,
                    name,
                    framework,
                    tags: tags.filter(|items| !items.is_empty()),
                },
            ));
        }

        matched.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let result = ListStateResult {
            success: true,
            documents: matched.into_iter().map(|(_, _, entry)| entry).collect(),
            message: match params.state_type.as_deref() {
                Some(filter) => format!("Listed agent state documents (state_type='{}').", filter),
                None => "Listed agent state documents.".to_string(),
            },
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Adopt an external file as signed agent state.
    ///
    /// Like sign_state but sets the origin to "adopted" and optionally records
    /// the source URL where the content was obtained.
    #[tool(
        name = "jacs_adopt_state",
        description = "Adopt an external file as signed agent state, marking it with 'adopted' origin."
    )]
    pub async fn jacs_adopt_state(
        &self,
        Parameters(params): Parameters<AdoptStateParams>,
    ) -> String {
        // Security: Validate file_path to prevent path traversal attacks via prompt injection.
        if let Err(e) = require_relative_path_safe(&params.file_path) {
            let result = AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Path validation failed".to_string(),
                error: Some(format!("PATH_TRAVERSAL_BLOCKED: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if let Err(error_code) = validate_state_file_root(&params.file_path) {
            let result = AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "State file access is restricted to approved JACS data roots.".to_string(),
                error: Some(error_code),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Create the agent state document with file reference
        let mut doc = match agentstate_crud::create_agentstate_with_file(
            &params.state_type,
            &params.name,
            &params.file_path,
            true, // embed for MCP document-centric reads/updates
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = AdoptStateResult {
                    success: false,
                    jacs_document_id: None,
                    state_type: params.state_type,
                    name: params.name,
                    message: "Failed to create agent state document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Set description if provided
        if let Some(desc) = &params.description {
            doc["jacsAgentStateDescription"] = serde_json::json!(desc);
        }

        // Set origin as "adopted" with optional source URL
        if let Err(e) = agentstate_crud::set_agentstate_origin(
            &mut doc,
            "adopted",
            params.source_url.as_deref(),
        ) {
            let result = AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Failed to set adopted origin".to_string(),
                error: Some(e),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Sign the document
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            Some(true),
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&AdoptStateResult {
                            success: false,
                            jacs_document_id: None,
                            state_type: params.state_type,
                            name: params.name,
                            message: "Failed to determine the adopted document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&AdoptStateResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        state_type: params.state_type,
                        name: params.name,
                        message: "Failed to persist adopted state document".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

                AdoptStateResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    state_type: params.state_type,
                    name: params.name,
                    message: format!(
                        "Successfully adopted and signed state file '{}' (origin: adopted{})",
                        params.file_path,
                        params
                            .source_url
                            .as_ref()
                            .map(|u| format!(", source: {}", u))
                            .unwrap_or_default()
                    ),
                    error: None,
                }
            }
            Err(e) => AdoptStateResult {
                success: false,
                jacs_document_id: None,
                state_type: params.state_type,
                name: params.name,
                message: "Failed to sign adopted document".to_string(),
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Create a new JACS agent programmatically.
    ///
    /// This is the programmatic equivalent of `jacs create`. It generates
    /// a new agent with cryptographic keys and returns the agent info.
    /// Requires JACS_MCP_ALLOW_REGISTRATION=true for security.
    #[tool(
        name = "jacs_create_agent",
        description = "Create a new JACS agent with cryptographic keys (programmatic)."
    )]
    pub async fn jacs_create_agent(
        &self,
        Parameters(params): Parameters<CreateAgentProgrammaticParams>,
    ) -> String {
        // Require explicit opt-in for agent creation (same gate as registration)
        if !self.registration_allowed {
            let result = CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Agent creation is disabled. Set JACS_MCP_ALLOW_REGISTRATION=true \
                          environment variable to enable."
                    .to_string(),
                error: Some("REGISTRATION_NOT_ALLOWED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if !inline_secrets_allowed() {
            let result = CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Inline passwords are disabled for MCP. Use an operator-provided \
                          secret channel or set JACS_MCP_ALLOW_INLINE_SECRETS=true to opt in."
                    .to_string(),
                error: Some("INLINE_SECRET_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if let Err(e) =
            validate_optional_relative_path("data_directory", params.data_directory.as_ref())
        {
            let result = CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Agent creation directory validation failed".to_string(),
                error: Some(format!("PATH_TRAVERSAL_BLOCKED: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if let Err(e) =
            validate_optional_relative_path("key_directory", params.key_directory.as_ref())
        {
            let result = CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Agent creation directory validation failed".to_string(),
                error: Some(format!("PATH_TRAVERSAL_BLOCKED: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = match jacs_binding_core::create_agent_programmatic(
            &params.name,
            &params.password,
            params.algorithm.as_deref(),
            params.data_directory.as_deref(),
            params.key_directory.as_deref(),
            None, // config_path
            params.agent_type.as_deref(),
            params.description.as_deref(),
            None, // domain
            None, // default_storage
        ) {
            Ok(info_json) => {
                // Parse the info JSON to extract agent_id
                let agent_id = serde_json::from_str::<serde_json::Value>(&info_json)
                    .ok()
                    .and_then(|v| v.get("agent_id").and_then(|a| a.as_str()).map(String::from));

                CreateAgentProgrammaticResult {
                    success: true,
                    agent_id,
                    name: params.name,
                    message: "Agent created successfully".to_string(),
                    error: None,
                }
            }
            Err(e) => CreateAgentProgrammaticResult {
                success: false,
                agent_id: None,
                name: params.name,
                message: "Failed to create agent".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Re-encrypt the agent's private key with a new password.
    ///
    /// Decrypts the private key with the old password and re-encrypts it
    /// with the new password. The key itself does not change.
    #[tool(
        name = "jacs_reencrypt_key",
        description = "Re-encrypt the agent's private key with a new password."
    )]
    pub async fn jacs_reencrypt_key(
        &self,
        Parameters(params): Parameters<ReencryptKeyParams>,
    ) -> String {
        if !inline_secrets_allowed() {
            let result = ReencryptKeyResult {
                success: false,
                message: "Inline passwords are disabled for MCP. Use an operator-provided \
                          secret channel or set JACS_MCP_ALLOW_INLINE_SECRETS=true to opt in."
                    .to_string(),
                error: Some("INLINE_SECRET_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = match self
            .agent
            .reencrypt_key(&params.old_password, &params.new_password)
        {
            Ok(()) => ReencryptKeyResult {
                success: true,
                message: "Private key re-encrypted successfully with new password".to_string(),
                error: None,
            },
            Err(e) => ReencryptKeyResult {
                success: false,
                message: "Failed to re-encrypt private key".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Run a read-only JACS security audit. Returns JSON with risks, health_checks, summary.
    #[tool(
        name = "jacs_audit",
        description = "Run a read-only JACS security audit and health checks."
    )]
    pub async fn jacs_audit(&self, Parameters(params): Parameters<JacsAuditParams>) -> String {
        match jacs_binding_core::audit(params.config_path.as_deref(), params.recent_n) {
            Ok(json) => json,
            Err(e) => serde_json::json!({
                "error": true,
                "message": e.to_string()
            })
            .to_string(),
        }
    }

    /// Record an audit trail event as a signed agentstate document with type "hook".
    ///
    /// Builds an agentstate document containing the action, target, details, and tags,
    /// then signs and persists it. All audit entries are private and use the "hook" state type.
    #[tool(
        name = "jacs_audit_log",
        description = "Record a tool-use, data-access, or other event as a cryptographically signed audit trail entry."
    )]
    pub async fn jacs_audit_log(&self, Parameters(params): Parameters<AuditLogParams>) -> String {
        // Build the audit entry content as JSON.
        let timestamp = format_iso8601(std::time::SystemTime::now());
        let mut content_obj = serde_json::json!({
            "action": params.action,
            "timestamp": timestamp,
        });
        if let Some(ref target) = params.target {
            content_obj["target"] = serde_json::json!(target);
        }
        if let Some(ref details) = params.details {
            content_obj["details"] = serde_json::json!(details);
        }
        if let Some(ref tags) = params.tags {
            content_obj["tags"] = serde_json::json!(tags);
        }

        let content_str = serde_json::to_string_pretty(&content_obj).unwrap_or_default();

        // Create an agentstate document with inline content.
        let name = format!("audit_{}_{}", params.action, &timestamp[..10]);
        let mut doc = match agentstate_crud::create_agentstate_with_content(
            "hook",
            &name,
            &content_str,
            "application/json",
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = AuditLogResult {
                    success: false,
                    jacs_document_id: None,
                    action: params.action,
                    message: "Failed to create audit entry document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Set tags if provided.
        if let Some(tags) = &params.tags {
            let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
            let _ = agentstate_crud::set_agentstate_tags(&mut doc, tag_refs);
        }

        // Always private, origin "authored".
        let _ = agentstate_crud::set_agentstate_origin(&mut doc, "authored", None);
        doc["jacsVisibility"] = serde_json::json!("private");

        // Sign and persist.
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None,       // custom_schema
            None,       // outputfilename
            true,       // no_save
            None,       // attachments
            Some(true), // embed
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&AuditLogResult {
                            success: false,
                            jacs_document_id: None,
                            action: params.action,
                            message: "Failed to determine the signed document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&AuditLogResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        action: params.action,
                        message: "Failed to persist signed audit entry".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

                AuditLogResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    action: params.action,
                    message: "Audit entry recorded successfully".to_string(),
                    error: None,
                }
            }
            Err(e) => AuditLogResult {
                success: false,
                jacs_document_id: None,
                action: params.action,
                message: "Failed to sign audit entry document".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Query the audit trail by action type, target, and/or time range.
    ///
    /// Iterates over all stored documents, filters to hook-type agentstate
    /// documents, and applies optional action/target/time filters.
    #[tool(
        name = "jacs_audit_query",
        description = "Search the audit trail by action type, target, and/or time range."
    )]
    pub async fn jacs_audit_query(
        &self,
        Parameters(params): Parameters<AuditQueryParams>,
    ) -> String {
        let keys = match self.agent.list_document_keys() {
            Ok(keys) => keys,
            Err(e) => {
                let result = AuditQueryResult {
                    success: false,
                    entries: Vec::new(),
                    total: 0,
                    message: "Failed to enumerate stored documents".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let limit = params.limit.unwrap_or(50) as usize;
        let offset = params.offset.unwrap_or(0) as usize;
        let mut matched: Vec<(String, AuditQueryEntry)> = Vec::new();

        for key in keys {
            let doc_string = match self.agent.get_document_by_id(&key) {
                Ok(doc) => doc,
                Err(_) => continue,
            };
            let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
                Ok(doc) => doc,
                Err(_) => continue,
            };

            // Must be agentstate with type "hook".
            if doc.get("jacsType").and_then(|v| v.as_str()) != Some("agentstate") {
                continue;
            }
            if value_string(&doc, "jacsAgentStateType").as_deref() != Some("hook") {
                continue;
            }

            // Parse the embedded audit content.
            let content_str = extract_embedded_state_content(&doc).unwrap_or_default();
            let content: serde_json::Value =
                serde_json::from_str(&content_str).unwrap_or(serde_json::Value::Null);

            let action = content
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target = content
                .get("target")
                .and_then(|v| v.as_str())
                .map(String::from);
            let timestamp = content
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let details = content
                .get("details")
                .and_then(|v| v.as_str())
                .map(String::from);

            // Apply filters.
            if let Some(ref filter_action) = params.action {
                if action != *filter_action {
                    continue;
                }
            }
            if let Some(ref filter_target) = params.target {
                match target.as_deref() {
                    Some(t) if t == filter_target.as_str() => {}
                    _ => continue,
                }
            }
            if let Some(ref start) = params.start_time {
                if timestamp.as_str() < start.as_str() {
                    continue;
                }
            }
            if let Some(ref end) = params.end_time {
                if timestamp.as_str() > end.as_str() {
                    continue;
                }
            }

            matched.push((
                timestamp.clone(),
                AuditQueryEntry {
                    jacs_document_id: key,
                    action,
                    target,
                    timestamp,
                    details,
                },
            ));
        }

        // Sort by timestamp descending (newest first).
        matched.sort_by(|a, b| b.0.cmp(&a.0));
        let total = matched.len();
        let entries: Vec<AuditQueryEntry> = matched
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(_, entry)| entry)
            .collect();

        let result = AuditQueryResult {
            success: true,
            entries,
            total,
            message: format!("Found {} audit entries", total),
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Export audit trail entries for a time period as a signed JACS document.
    ///
    /// Queries all hook-type agentstate documents within the time range,
    /// collects them into a JSON array, wraps in a new JACS document, and signs it.
    #[tool(
        name = "jacs_audit_export",
        description = "Export audit trail entries for a time period as a single signed JACS document."
    )]
    pub async fn jacs_audit_export(
        &self,
        Parameters(params): Parameters<AuditExportParams>,
    ) -> String {
        let keys = match self.agent.list_document_keys() {
            Ok(keys) => keys,
            Err(e) => {
                let result = AuditExportResult {
                    success: false,
                    signed_bundle: None,
                    entry_count: 0,
                    message: "Failed to enumerate stored documents".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut entries: Vec<serde_json::Value> = Vec::new();

        for key in keys {
            let doc_string = match self.agent.get_document_by_id(&key) {
                Ok(doc) => doc,
                Err(_) => continue,
            };
            let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
                Ok(doc) => doc,
                Err(_) => continue,
            };

            // Must be agentstate with type "hook".
            if doc.get("jacsType").and_then(|v| v.as_str()) != Some("agentstate") {
                continue;
            }
            if value_string(&doc, "jacsAgentStateType").as_deref() != Some("hook") {
                continue;
            }

            // Parse the embedded audit content for time filtering.
            let content_str = extract_embedded_state_content(&doc).unwrap_or_default();
            let content: serde_json::Value =
                serde_json::from_str(&content_str).unwrap_or(serde_json::Value::Null);

            let timestamp = content
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action = content.get("action").and_then(|v| v.as_str()).unwrap_or("");

            // Apply time range filter.
            if timestamp < params.start_time.as_str() {
                continue;
            }
            if timestamp > params.end_time.as_str() {
                continue;
            }

            // Apply optional action filter.
            if let Some(ref filter_action) = params.action {
                if action != filter_action.as_str() {
                    continue;
                }
            }

            entries.push(content);
        }

        let entry_count = entries.len();

        // Wrap entries into a single bundle document.
        let bundle_content = serde_json::json!({
            "audit_export": true,
            "start_time": params.start_time,
            "end_time": params.end_time,
            "entry_count": entry_count,
            "entries": entries,
        });
        let bundle_str = serde_json::to_string_pretty(&bundle_content).unwrap_or_default();

        let name = format!(
            "audit_export_{}_to_{}",
            &params.start_time[..10.min(params.start_time.len())],
            &params.end_time[..10.min(params.end_time.len())]
        );

        let mut doc = match agentstate_crud::create_agentstate_with_content(
            "hook",
            &name,
            &bundle_str,
            "application/json",
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = AuditExportResult {
                    success: false,
                    signed_bundle: None,
                    entry_count,
                    message: "Failed to create audit export document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let _ = agentstate_crud::set_agentstate_origin(&mut doc, "authored", None);
        doc["jacsVisibility"] = serde_json::json!("private");

        // Sign and persist.
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None,       // custom_schema
            None,       // outputfilename
            true,       // no_save
            None,       // attachments
            Some(true), // embed
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&AuditExportResult {
                            success: false,
                            signed_bundle: None,
                            entry_count,
                            message: "Failed to determine the signed document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&AuditExportResult {
                        success: false,
                        signed_bundle: Some(signed_doc_string),
                        entry_count,
                        message: "Audit export signed but failed to persist".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

                AuditExportResult {
                    success: true,
                    signed_bundle: Some(signed_doc_string),
                    entry_count,
                    message: format!(
                        "Exported {} audit entries as signed bundle (id: {})",
                        entry_count, doc_id
                    ),
                    error: None,
                }
            }
            Err(e) => AuditExportResult {
                success: false,
                signed_bundle: None,
                entry_count,
                message: "Failed to sign audit export document".to_string(),
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Search across all signed documents using the configured document service.
    #[tool(
        name = "jacs_search",
        description = "Search across all signed documents using the unified search interface."
    )]
    pub async fn jacs_search(&self, Parameters(params): Parameters<SearchParams>) -> String {
        let Some(service) = self.document_service.as_ref() else {
            let result = SearchResult {
                success: false,
                results: Vec::new(),
                total: 0,
                search_method: None,
                message: "Document service is not available for the configured storage backend"
                    .to_string(),
                error: Some("document_service_unavailable".to_string()),
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            return inject_meta(&serialized, None);
        };

        let query_text = params.query.clone();
        let query = jacs::search::SearchQuery {
            query: params.query,
            jacs_type: params.jacs_type,
            agent_id: params.agent_id,
            field_filter: params.field_filter.map(|filter| jacs::search::FieldFilter {
                field_path: filter.field_path,
                value: filter.value,
            }),
            limit: params.limit.unwrap_or(20) as usize,
            offset: params.offset.unwrap_or(0) as usize,
            min_score: params.min_score,
        };

        let search_results = match service.search(query) {
            Ok(results) => results,
            Err(err) => {
                let result = SearchResult {
                    success: false,
                    results: Vec::new(),
                    total: 0,
                    search_method: None,
                    message: "Search failed".to_string(),
                    error: Some(err.to_string()),
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                return inject_meta(&serialized, None);
            }
        };

        let search_method = match search_results.method {
            jacs::search::SearchMethod::FullText => "fulltext",
            jacs::search::SearchMethod::Vector => "vector",
            jacs::search::SearchMethod::Hybrid => "hybrid",
            jacs::search::SearchMethod::FieldMatch => "field_match",
            jacs::search::SearchMethod::Unsupported => "unsupported",
        }
        .to_string();

        let results = search_results
            .results
            .into_iter()
            .map(|hit| {
                let doc = &hit.document.value;
                let name = value_string(doc, "jacsAgentStateName")
                    .or_else(|| value_string(doc, "jacsName"))
                    .or_else(|| value_string(doc, "name"));
                let snippet = extract_embedded_state_content(doc)
                    .or_else(|| value_string(doc, "jacsDescription"))
                    .or_else(|| value_string(doc, "content"));

                SearchResultEntry {
                    jacs_document_id: hit.document.getkey(),
                    jacs_type: Some(hit.document.jacs_type.clone()),
                    name,
                    snippet,
                    score: Some(hit.score),
                    search_method: Some(search_method.clone()),
                }
            })
            .collect::<Vec<_>>();

        let total = search_results.total_count;
        let result = SearchResult {
            success: true,
            results,
            total,
            search_method: Some(search_method),
            message: format!("Found {} documents matching '{}'", total, query_text),
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Create and sign a message document for sending to another agent.
    ///
    /// Builds a JSON message envelope with sender/recipient IDs, content, timestamp,
    /// and a unique message ID, then signs it using the local agent's keys.
    #[tool(
        name = "jacs_message_send",
        description = "Create and sign a message for sending to another agent."
    )]
    pub async fn jacs_message_send(
        &self,
        Parameters(params): Parameters<MessageSendParams>,
    ) -> String {
        // Validate recipient agent ID
        if let Err(e) = validate_agent_id(&params.recipient_agent_id) {
            let result = MessageSendResult {
                success: false,
                jacs_document_id: None,
                signed_message: None,
                error: Some(e),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let sender_id = match self.agent.get_agent_id() {
            Ok(agent_id) => agent_id,
            Err(e) => {
                let result = MessageSendResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!("Failed to determine sender agent ID: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let content_type = params
            .content_type
            .unwrap_or_else(|| "text/plain".to_string());
        let message_id = Uuid::new_v4().to_string();
        let timestamp = format_iso8601(std::time::SystemTime::now());

        // Build the message document
        let message_doc = serde_json::json!({
            "jacsType": "message",
            "jacsLevel": "artifact",
            "jacsMessageId": message_id,
            "jacsMessageSenderId": sender_id,
            "jacsMessageRecipientId": params.recipient_agent_id,
            "jacsMessageContent": params.content,
            "jacsMessageContentType": content_type,
            "jacsMessageTimestamp": timestamp,
        });

        let doc_string = message_doc.to_string();

        // Sign the document
        let result = match self.agent.create_document(
            &doc_string,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            None, // embed
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&MessageSendResult {
                            success: false,
                            jacs_document_id: None,
                            signed_message: Some(signed_doc_string),
                            error: Some("Failed to determine the signed message ID".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&MessageSendResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        signed_message: Some(signed_doc_string),
                        error: Some(format!("Failed to persist signed message: {}", e)),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

                MessageSendResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    signed_message: Some(signed_doc_string),
                    error: None,
                }
            }
            Err(e) => MessageSendResult {
                success: false,
                jacs_document_id: None,
                signed_message: None,
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Update and re-sign an existing message document with new content.
    ///
    /// Loads the message by its JACS document ID, replaces the content fields,
    /// and creates a new signed version.
    #[tool(
        name = "jacs_message_update",
        description = "Update and re-sign an existing message document with new content."
    )]
    pub async fn jacs_message_update(
        &self,
        Parameters(params): Parameters<MessageUpdateParams>,
    ) -> String {
        match self.agent.verify_document_by_id(&params.jacs_id) {
            Ok(true) => {}
            Ok(false) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Existing document '{}' failed signature verification",
                        params.jacs_id
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
            Err(e) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Failed to load document '{}': {}",
                        params.jacs_id, e
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let existing_doc_string = match self.agent.get_document_by_id(&params.jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Failed to load document '{}' for update: {}",
                        params.jacs_id, e
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut updated_doc = match serde_json::from_str::<serde_json::Value>(&existing_doc_string)
        {
            Ok(doc) => doc,
            Err(e) => {
                let result = MessageUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    signed_message: None,
                    error: Some(format!(
                        "Stored document '{}' is not valid JSON: {}",
                        params.jacs_id, e
                    )),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let content_type = params
            .content_type
            .unwrap_or_else(|| "text/plain".to_string());
        let timestamp = format_iso8601(std::time::SystemTime::now());

        updated_doc["jacsType"] = serde_json::json!("message");
        updated_doc["jacsLevel"] = serde_json::json!("artifact");
        updated_doc["jacsMessageContent"] = serde_json::json!(params.content);
        updated_doc["jacsMessageContentType"] = serde_json::json!(content_type);
        updated_doc["jacsMessageTimestamp"] = serde_json::json!(timestamp);

        let doc_string = updated_doc.to_string();
        let result = match self
            .agent
            .update_document(&params.jacs_id, &doc_string, None, None)
        {
            Ok(updated_doc_string) => {
                let doc_id = extract_document_lookup_key_from_str(&updated_doc_string)
                    .unwrap_or_else(|| params.jacs_id.clone());

                MessageUpdateResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    signed_message: Some(updated_doc_string),
                    error: None,
                }
            }
            Err(e) => MessageUpdateResult {
                success: false,
                jacs_document_id: None,
                signed_message: None,
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Co-sign (agree to) a received signed message.
    ///
    /// Verifies the original message's signature, then creates an agreement document
    /// that references the original and is signed by the local agent.
    #[tool(
        name = "jacs_message_agree",
        description = "Verify and co-sign a received message, creating a signed agreement document."
    )]
    pub async fn jacs_message_agree(
        &self,
        Parameters(params): Parameters<MessageAgreeParams>,
    ) -> String {
        // Verify the original document's signature first
        match self.agent.verify_document(&params.signed_message) {
            Ok(true) => {} // Signature valid, proceed
            Ok(false) => {
                let result = MessageAgreeResult {
                    success: false,
                    original_document_id: None,
                    agreement_document_id: None,
                    signed_agreement: None,
                    error: Some("Original message signature verification failed".to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
            Err(e) => {
                let result = MessageAgreeResult {
                    success: false,
                    original_document_id: None,
                    agreement_document_id: None,
                    signed_agreement: None,
                    error: Some(format!("Failed to verify original message: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // Extract the original document ID
        let original_doc_id = extract_document_lookup_key_from_str(&params.signed_message)
            .unwrap_or_else(|| "unknown".to_string());

        let our_agent_id = self
            .agent
            .get_agent_id()
            .unwrap_or_else(|_| "unknown".to_string());

        let timestamp = format_iso8601(std::time::SystemTime::now());

        // Create an agreement document that references the original
        let agreement_doc = serde_json::json!({
            "jacsAgreementType": "message_acknowledgment",
            "jacsAgreementOriginalDocumentId": original_doc_id,
            "jacsAgreementAgentId": our_agent_id,
            "jacsAgreementTimestamp": timestamp,
        });

        let doc_string = agreement_doc.to_string();

        // Sign the agreement document
        let result = match self.agent.create_document(
            &doc_string,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            None, // embed
        ) {
            Ok(signed_agreement_string) => {
                let agreement_id = extract_document_lookup_key_from_str(&signed_agreement_string)
                    .unwrap_or_else(|| "unknown".to_string());

                MessageAgreeResult {
                    success: true,
                    original_document_id: Some(original_doc_id),
                    agreement_document_id: Some(agreement_id),
                    signed_agreement: Some(signed_agreement_string),
                    error: None,
                }
            }
            Err(e) => MessageAgreeResult {
                success: false,
                original_document_id: Some(original_doc_id),
                agreement_document_id: None,
                signed_agreement: None,
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Verify and extract content from a received signed message.
    ///
    /// Checks the cryptographic signature, then extracts the message content,
    /// sender ID, content type, and timestamp.
    #[tool(
        name = "jacs_message_receive",
        description = "Verify a received signed message and extract its content and sender information."
    )]
    pub async fn jacs_message_receive(
        &self,
        Parameters(params): Parameters<MessageReceiveParams>,
    ) -> String {
        // Verify the document's signature
        let signature_valid = match self.agent.verify_document(&params.signed_message) {
            Ok(valid) => valid,
            Err(e) => {
                let result = MessageReceiveResult {
                    success: false,
                    sender_agent_id: None,
                    content: None,
                    content_type: None,
                    timestamp: None,
                    signature_valid: false,
                    error: Some(format!("Failed to verify message signature: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Parse the document to extract fields
        let doc: serde_json::Value = match serde_json::from_str(&params.signed_message) {
            Ok(v) => v,
            Err(e) => {
                let result = MessageReceiveResult {
                    success: false,
                    sender_agent_id: None,
                    content: None,
                    content_type: None,
                    timestamp: None,
                    signature_valid,
                    error: Some(format!("Failed to parse message JSON: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Extract message fields
        let sender_agent_id = doc
            .get("jacsMessageSenderId")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| {
                // Fall back to signature's agentID
                doc.get("jacsSignature")
                    .and_then(|s| s.get("agentID"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        let content = doc
            .get("jacsMessageContent")
            .and_then(|v| v.as_str())
            .map(String::from);

        let content_type = doc
            .get("jacsMessageContentType")
            .and_then(|v| v.as_str())
            .map(String::from);

        let timestamp = doc
            .get("jacsMessageTimestamp")
            .and_then(|v| v.as_str())
            .map(String::from);

        if !signature_valid {
            let result = MessageReceiveResult {
                success: false,
                sender_agent_id: None,
                content: None,
                content_type: None,
                timestamp: None,
                signature_valid: false,
                error: Some(
                    "Message signature is INVALID — content may have been tampered with"
                        .to_string(),
                ),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let result = MessageReceiveResult {
            success: true,
            sender_agent_id,
            content,
            content_type,
            timestamp,
            signature_valid,
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, Some(&doc))
    }

    // =========================================================================
    // Agreement tools — multi-party cryptographic agreements
    // =========================================================================

    /// Create a multi-party agreement that other agents can co-sign.
    ///
    /// The agreement specifies which agents must sign, optional quorum (M-of-N),
    /// timeout, and algorithm constraints. The returned document should be passed
    /// to other agents for signing via `jacs_sign_agreement`.
    #[tool(
        name = "jacs_create_agreement",
        description = "Create a multi-party cryptographic agreement. Specify which agents must sign, \
                       optional quorum (e.g., 2-of-3), timeout deadline, and algorithm constraints. \
                       Returns a signed agreement document to pass to other agents for co-signing."
    )]
    pub async fn jacs_create_agreement(
        &self,
        Parameters(params): Parameters<CreateAgreementParams>,
    ) -> String {
        // Create the base document first
        let signed_doc = match self.agent.create_document(
            &params.document,
            None, // custom_schema
            None, // outputfilename
            true, // no_save
            None, // attachments
            None, // embed
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = CreateAgreementResult {
                    success: false,
                    agreement_id: None,
                    signed_agreement: None,
                    error: Some(format!("Failed to create document: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Create the agreement on the document
        let result = match self.agent.create_agreement_with_options(
            &signed_doc,
            params.agent_ids,
            params.question,
            params.context,
            None, // agreement_fieldname (use default)
            params.timeout,
            params.quorum,
            params.required_algorithms,
            params.minimum_strength,
        ) {
            Ok(agreement_string) => {
                let agreement_id = extract_document_lookup_key_from_str(&agreement_string)
                    .unwrap_or_else(|| "unknown".to_string());

                CreateAgreementResult {
                    success: true,
                    agreement_id: Some(agreement_id),
                    signed_agreement: Some(agreement_string),
                    error: None,
                }
            }
            Err(e) => CreateAgreementResult {
                success: false,
                agreement_id: None,
                signed_agreement: None,
                error: Some(format!("Failed to create agreement: {}", e)),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Co-sign an existing agreement.
    ///
    /// Adds this agent's cryptographic signature to the agreement. The agent's
    /// algorithm must satisfy any constraints specified when the agreement was created.
    #[tool(
        name = "jacs_sign_agreement",
        description = "Co-sign an existing agreement. Adds your agent's cryptographic signature. \
                       The agreement may have algorithm constraints that your agent must satisfy."
    )]
    pub async fn jacs_sign_agreement(
        &self,
        Parameters(params): Parameters<SignAgreementParams>,
    ) -> String {
        let result = match self
            .agent
            .sign_agreement(&params.signed_agreement, params.agreement_fieldname)
        {
            Ok(signed_string) => {
                // Count signatures
                let sig_count =
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&signed_string) {
                        v.get("jacsAgreement")
                            .and_then(|a| a.get("signatures"))
                            .and_then(|s| s.as_array())
                            .map(|arr| arr.len())
                            .unwrap_or(0)
                    } else {
                        0
                    };

                SignAgreementResult {
                    success: true,
                    signed_agreement: Some(signed_string),
                    signature_count: Some(sig_count),
                    error: None,
                }
            }
            Err(e) => SignAgreementResult {
                success: false,
                signed_agreement: None,
                signature_count: None,
                error: Some(format!("Failed to sign agreement: {}", e)),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Check the status of an agreement.
    ///
    /// Returns whether quorum is met, which agents have signed, whether the
    /// agreement has expired, and how many more signatures are needed.
    #[tool(
        name = "jacs_check_agreement",
        description = "Check agreement status: who has signed, whether quorum is met, \
                       whether it has expired, and who still needs to sign."
    )]
    pub async fn jacs_check_agreement(
        &self,
        Parameters(params): Parameters<CheckAgreementParams>,
    ) -> String {
        let fieldname = params
            .agreement_fieldname
            .unwrap_or_else(|| "jacsAgreement".to_string());

        if let Err(e) = self
            .agent
            .check_agreement(&params.signed_agreement, Some(fieldname.clone()))
        {
            let result = CheckAgreementResult {
                success: false,
                complete: false,
                total_agents: 0,
                signatures_collected: 0,
                signatures_required: 0,
                quorum_met: false,
                expired: false,
                signed_by: None,
                unsigned: None,
                timeout: None,
                error: Some(format!("Failed to check agreement: {}", e)),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Parse the verified agreement to extract status details.
        let doc: serde_json::Value = match serde_json::from_str(&params.signed_agreement) {
            Ok(v) => v,
            Err(e) => {
                let result = CheckAgreementResult {
                    success: false,
                    complete: false,
                    total_agents: 0,
                    signatures_collected: 0,
                    signatures_required: 0,
                    quorum_met: false,
                    expired: false,
                    signed_by: None,
                    unsigned: None,
                    timeout: None,
                    error: Some(format!("Failed to parse agreement JSON: {}", e)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let agreement = match doc.get(&fieldname) {
            Some(a) => a,
            None => {
                let result = CheckAgreementResult {
                    success: false,
                    complete: false,
                    total_agents: 0,
                    signatures_collected: 0,
                    signatures_required: 0,
                    quorum_met: false,
                    expired: false,
                    signed_by: None,
                    unsigned: None,
                    timeout: None,
                    error: Some(format!("No '{}' field found in document", fieldname)),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Extract agent IDs
        let agent_ids: Vec<String> = agreement
            .get("agentIDs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Extract signatures
        let signatures = agreement
            .get("signatures")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let signed_by: Vec<String> = signatures
            .iter()
            .filter_map(|sig| {
                sig.get("agentID")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();

        let signed_set: std::collections::HashSet<&str> =
            signed_by.iter().map(|s| s.as_str()).collect();
        let unsigned: Vec<String> = agent_ids
            .iter()
            .filter(|id| !signed_set.contains(id.as_str()))
            .cloned()
            .collect();

        // Quorum
        let quorum = agreement
            .get("quorum")
            .and_then(|v| v.as_u64())
            .map(|q| q as usize)
            .unwrap_or(agent_ids.len());
        let quorum_met = signed_by.len() >= quorum;

        // Timeout
        let timeout_str = agreement
            .get("timeout")
            .and_then(|v| v.as_str())
            .map(String::from);
        let expired = timeout_str
            .as_ref()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|deadline| chrono::Utc::now() > deadline)
            .unwrap_or(false);

        let complete = quorum_met && !expired;

        let result = CheckAgreementResult {
            success: true,
            complete,
            total_agents: agent_ids.len(),
            signatures_collected: signed_by.len(),
            signatures_required: quorum,
            quorum_met,
            expired,
            signed_by: Some(signed_by),
            unsigned: Some(unsigned),
            timeout: timeout_str,
            error: None,
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    // =========================================================================
    // Document Sign / Verify tools
    // =========================================================================

    /// Sign arbitrary JSON content to create a cryptographically signed JACS document.
    #[tool(
        name = "jacs_sign_document",
        description = "Sign arbitrary JSON content to create a signed JACS document for attestation."
    )]
    pub async fn jacs_sign_document(
        &self,
        Parameters(params): Parameters<SignDocumentParams>,
    ) -> String {
        // Validate content is valid JSON
        let content_value: serde_json::Value = match serde_json::from_str(&params.content) {
            Ok(v) => v,
            Err(e) => {
                let result = SignDocumentResult {
                    success: false,
                    signed_document: None,
                    content_hash: None,
                    jacs_document_id: None,
                    message: "Content is not valid JSON".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Wrap content in a JACS-compatible envelope if it doesn't already have jacsType
        let doc_to_sign = if content_value.get("jacsType").is_some() {
            params.content.clone()
        } else {
            let wrapper = serde_json::json!({
                "jacsType": "document",
                "jacsLevel": "raw",
                "content": content_value,
            });
            wrapper.to_string()
        };

        // Sign via create_document (no_save=true)
        match self
            .agent
            .create_document(&doc_to_sign, None, None, true, None, None)
        {
            Ok(signed_doc_string) => {
                // Extract document ID and compute content hash
                let doc_id = extract_document_lookup_key_from_str(&signed_doc_string);

                let hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(signed_doc_string.as_bytes());
                    format!("{:x}", hasher.finalize())
                };

                let result = SignDocumentResult {
                    success: true,
                    signed_document: Some(signed_doc_string),
                    content_hash: Some(hash),
                    jacs_document_id: doc_id,
                    message: "Document signed successfully".to_string(),
                    error: None,
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                inject_meta(&serialized, Some(&content_value))
            }
            Err(e) => {
                let result = SignDocumentResult {
                    success: false,
                    signed_document: None,
                    content_hash: None,
                    jacs_document_id: None,
                    message: "Failed to sign document".to_string(),
                    error: Some(e.to_string()),
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                inject_meta(&serialized, None)
            }
        }
    }

    /// Verify a signed JACS document given its full JSON string.
    #[tool(
        name = "jacs_verify_document",
        description = "Verify a signed JACS document's hash and cryptographic signature."
    )]
    pub async fn jacs_verify_document(
        &self,
        Parameters(params): Parameters<VerifyDocumentParams>,
    ) -> String {
        if params.document.is_empty() {
            let result = VerifyDocumentResult {
                success: false,
                valid: false,
                signer_id: None,
                message: "Document string is empty".to_string(),
                error: Some("EMPTY_DOCUMENT".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Try verify_signature first (works for both self-signed and external docs)
        match self.agent.verify_signature(&params.document, None) {
            Ok(valid) => {
                // Try to extract signer ID from the document
                let signer_id = serde_json::from_str::<serde_json::Value>(&params.document)
                    .ok()
                    .and_then(|v| {
                        v.get("jacsSignature")
                            .and_then(|sig| sig.get("agentId").or_else(|| sig.get("agentID")))
                            .and_then(|id| id.as_str())
                            .map(String::from)
                    });

                let result = VerifyDocumentResult {
                    success: true,
                    valid,
                    signer_id,
                    message: if valid {
                        "Document verified successfully".to_string()
                    } else {
                        "Document signature verification failed".to_string()
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = VerifyDocumentResult {
                    success: false,
                    valid: false,
                    signer_id: None,
                    message: format!("Verification failed: {}", e),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // A2A Artifact Wrapping/Verification Tools
    // =========================================================================

    /// Wrap an A2A artifact with JACS provenance signature.
    #[tool(
        name = "jacs_wrap_a2a_artifact",
        description = "Wrap an A2A artifact with JACS provenance signature."
    )]
    pub async fn jacs_wrap_a2a_artifact(
        &self,
        Parameters(params): Parameters<WrapA2aArtifactParams>,
    ) -> String {
        if params.artifact_json.is_empty() {
            let result = WrapA2aArtifactResult {
                success: false,
                wrapped_artifact: None,
                message: "Artifact JSON is empty".to_string(),
                error: Some("EMPTY_ARTIFACT".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        #[allow(deprecated)]
        match self.agent.wrap_a2a_artifact(
            &params.artifact_json,
            &params.artifact_type,
            params.parent_signatures.as_deref(),
        ) {
            Ok(wrapped_json) => {
                let result = WrapA2aArtifactResult {
                    success: true,
                    wrapped_artifact: Some(wrapped_json),
                    message: "Artifact wrapped with JACS provenance".to_string(),
                    error: None,
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                inject_meta(&serialized, None)
            }
            Err(e) => {
                let result = WrapA2aArtifactResult {
                    success: false,
                    wrapped_artifact: None,
                    message: "Failed to wrap artifact".to_string(),
                    error: Some(e.to_string()),
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                inject_meta(&serialized, None)
            }
        }
    }

    /// Verify a JACS-wrapped A2A artifact.
    #[tool(
        name = "jacs_verify_a2a_artifact",
        description = "Verify a JACS-wrapped A2A artifact's signature and hash."
    )]
    pub async fn jacs_verify_a2a_artifact(
        &self,
        Parameters(params): Parameters<VerifyA2aArtifactParams>,
    ) -> String {
        if params.wrapped_artifact.is_empty() {
            let result = VerifyA2aArtifactResult {
                success: false,
                valid: false,
                verification_details: None,
                message: "Wrapped artifact JSON is empty".to_string(),
                error: Some("EMPTY_ARTIFACT".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match self.agent.verify_a2a_artifact(&params.wrapped_artifact) {
            Ok(details_json) => {
                let valid = extract_verify_a2a_valid(&details_json);
                let result = VerifyA2aArtifactResult {
                    success: true,
                    valid,
                    verification_details: Some(details_json),
                    message: if valid {
                        "Artifact verified successfully".to_string()
                    } else {
                        "Artifact verification found issues".to_string()
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = VerifyA2aArtifactResult {
                    success: false,
                    valid: false,
                    verification_details: None,
                    message: "Artifact verification failed".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Assess the trust level of a remote A2A agent.
    #[tool(
        name = "jacs_assess_a2a_agent",
        description = "Assess trust level of a remote A2A agent given its Agent Card."
    )]
    pub async fn jacs_assess_a2a_agent(
        &self,
        Parameters(params): Parameters<AssessA2aAgentParams>,
    ) -> String {
        if params.agent_card_json.is_empty() {
            let result = AssessA2aAgentResult {
                success: false,
                allowed: false,
                trust_level: None,
                policy: None,
                reason: None,
                message: "Agent Card JSON is empty".to_string(),
                error: Some("EMPTY_AGENT_CARD".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let policy_str = params.policy.as_deref().unwrap_or("verified");

        match self
            .agent
            .assess_a2a_agent(&params.agent_card_json, policy_str)
        {
            Ok(assessment_json) => {
                // Parse the assessment to extract fields for our result type
                let assessment: serde_json::Value =
                    serde_json::from_str(&assessment_json).unwrap_or_default();
                let allowed = assessment
                    .get("allowed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let trust_level = assessment
                    .get("trust_level")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let policy = assessment
                    .get("policy")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let reason = assessment
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let result = AssessA2aAgentResult {
                    success: true,
                    allowed,
                    trust_level,
                    policy,
                    reason: reason.clone(),
                    message: reason.unwrap_or_else(|| "Assessment complete".to_string()),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = AssessA2aAgentResult {
                    success: false,
                    allowed: false,
                    trust_level: None,
                    policy: Some(policy_str.to_string()),
                    reason: None,
                    message: "Trust assessment failed".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // Agent Card & Well-Known Tools
    // =========================================================================

    /// Export this agent's A2A Agent Card.
    #[tool(
        name = "jacs_export_agent_card",
        description = "Export this agent's A2A Agent Card as JSON for discovery."
    )]
    pub async fn jacs_export_agent_card(
        &self,
        Parameters(_params): Parameters<ExportAgentCardParams>,
    ) -> String {
        match self.agent.export_agent_card() {
            Ok(card_json) => {
                let result = ExportAgentCardResult {
                    success: true,
                    agent_card: Some(card_json),
                    message: "Agent Card exported successfully".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = ExportAgentCardResult {
                    success: false,
                    agent_card: None,
                    message: "Failed to export Agent Card".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Generate all .well-known documents for A2A discovery.
    #[tool(
        name = "jacs_generate_well_known",
        description = "Generate .well-known documents for A2A agent discovery."
    )]
    pub async fn jacs_generate_well_known(
        &self,
        Parameters(params): Parameters<GenerateWellKnownParams>,
    ) -> String {
        match self
            .agent
            .generate_well_known_documents(params.a2a_algorithm.as_deref())
        {
            Ok(docs_json) => {
                // Parse to count documents
                let count = serde_json::from_str::<Vec<serde_json::Value>>(&docs_json)
                    .map(|v| v.len())
                    .unwrap_or(0);
                let result = GenerateWellKnownResult {
                    success: true,
                    documents: Some(docs_json),
                    count,
                    message: format!("{} well-known document(s) generated", count),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = GenerateWellKnownResult {
                    success: false,
                    documents: None,
                    count: 0,
                    message: "Failed to generate well-known documents".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Export the local agent's full JACS JSON document.
    #[tool(
        name = "jacs_export_agent",
        description = "Export the local agent's full JACS JSON document."
    )]
    pub async fn jacs_export_agent(
        &self,
        Parameters(_params): Parameters<ExportAgentParams>,
    ) -> String {
        match self.agent.get_agent_json() {
            Ok(agent_json) => {
                // Try to extract the agent ID from the JSON
                let agent_id = serde_json::from_str::<serde_json::Value>(&agent_json)
                    .ok()
                    .and_then(|v| v.get("jacsId").and_then(|id| id.as_str()).map(String::from));
                let result = ExportAgentResult {
                    success: true,
                    agent_json: Some(agent_json),
                    agent_id,
                    message: "Agent document exported successfully".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = ExportAgentResult {
                    success: false,
                    agent_json: None,
                    agent_id: None,
                    message: "Failed to export agent document".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // Trust Store Tools
    // =========================================================================

    /// Add an agent to the local trust store.
    ///
    /// The agent's self-signature is cryptographically verified before it is
    /// added. If verification fails, the agent is NOT trusted.
    #[tool(
        name = "jacs_trust_agent",
        description = "Add an agent to the local trust store after verifying its self-signature."
    )]
    pub async fn jacs_trust_agent(
        &self,
        Parameters(params): Parameters<TrustAgentParams>,
    ) -> String {
        if params.agent_json.is_empty() {
            let result = TrustAgentResult {
                success: false,
                agent_id: None,
                message: "Agent JSON is empty".to_string(),
                error: Some("EMPTY_AGENT_JSON".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match jacs_binding_core::trust_agent(&params.agent_json) {
            Ok(agent_id) => {
                let result = TrustAgentResult {
                    success: true,
                    agent_id: Some(agent_id.clone()),
                    message: format!("Agent {} added to trust store", agent_id),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = TrustAgentResult {
                    success: false,
                    agent_id: None,
                    message: "Failed to trust agent".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Remove an agent from the local trust store.
    ///
    /// # Security
    ///
    /// Untrusting requires `JACS_MCP_ALLOW_UNTRUST=true` environment variable.
    /// This prevents prompt injection attacks from removing trusted agents
    /// without user consent.
    #[tool(
        name = "jacs_untrust_agent",
        description = "Remove an agent from the local trust store. Requires JACS_MCP_ALLOW_UNTRUST=true."
    )]
    pub async fn jacs_untrust_agent(
        &self,
        Parameters(params): Parameters<UntrustAgentParams>,
    ) -> String {
        // Security check: Untrusting must be explicitly enabled
        if !self.untrust_allowed {
            let result = UntrustAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                message: "Untrusting is disabled for security. \
                          To enable, set JACS_MCP_ALLOW_UNTRUST=true environment variable \
                          when starting the MCP server."
                    .to_string(),
                error: Some("UNTRUST_DISABLED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        if params.agent_id.is_empty() {
            let result = UntrustAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                message: "Agent ID is empty".to_string(),
                error: Some("EMPTY_AGENT_ID".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match jacs_binding_core::untrust_agent(&params.agent_id) {
            Ok(()) => {
                let result = UntrustAgentResult {
                    success: true,
                    agent_id: params.agent_id.clone(),
                    message: format!("Agent {} removed from trust store", params.agent_id),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = UntrustAgentResult {
                    success: false,
                    agent_id: params.agent_id.clone(),
                    message: "Failed to untrust agent".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// List all trusted agent IDs in the local trust store.
    #[tool(
        name = "jacs_list_trusted_agents",
        description = "List all agent IDs in the local trust store."
    )]
    pub async fn jacs_list_trusted_agents(
        &self,
        Parameters(_params): Parameters<ListTrustedAgentsParams>,
    ) -> String {
        match jacs_binding_core::list_trusted_agents() {
            Ok(agent_ids) => {
                let count = agent_ids.len();
                let result = ListTrustedAgentsResult {
                    success: true,
                    agent_ids,
                    count,
                    message: format!("{} trusted agent(s) found", count),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = ListTrustedAgentsResult {
                    success: false,
                    agent_ids: vec![],
                    count: 0,
                    message: "Failed to list trusted agents".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Check whether a specific agent is in the local trust store.
    #[tool(
        name = "jacs_is_trusted",
        description = "Check whether a specific agent is in the local trust store."
    )]
    pub async fn jacs_is_trusted(&self, Parameters(params): Parameters<IsTrustedParams>) -> String {
        if params.agent_id.is_empty() {
            let result = IsTrustedResult {
                success: false,
                agent_id: params.agent_id.clone(),
                trusted: false,
                message: "Agent ID is empty".to_string(),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        let trusted = jacs_binding_core::is_trusted(&params.agent_id);
        let result = IsTrustedResult {
            success: true,
            agent_id: params.agent_id.clone(),
            trusted,
            message: if trusted {
                format!("Agent {} is trusted", params.agent_id)
            } else {
                format!("Agent {} is NOT trusted", params.agent_id)
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Retrieve the full agent JSON document for a trusted agent.
    #[tool(
        name = "jacs_get_trusted_agent",
        description = "Retrieve the full agent JSON for a trusted agent from the local trust store."
    )]
    pub async fn jacs_get_trusted_agent(
        &self,
        Parameters(params): Parameters<GetTrustedAgentParams>,
    ) -> String {
        if params.agent_id.is_empty() {
            let result = GetTrustedAgentResult {
                success: false,
                agent_id: params.agent_id.clone(),
                agent_json: None,
                message: "Agent ID is empty".to_string(),
                error: Some("EMPTY_AGENT_ID".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        match jacs_binding_core::get_trusted_agent(&params.agent_id) {
            Ok(agent_json) => {
                let result = GetTrustedAgentResult {
                    success: true,
                    agent_id: params.agent_id.clone(),
                    agent_json: Some(agent_json),
                    message: format!("Retrieved trusted agent {}", params.agent_id),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = GetTrustedAgentResult {
                    success: false,
                    agent_id: params.agent_id.clone(),
                    agent_json: None,
                    message: "Failed to get trusted agent".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    // =========================================================================
    // Attestation Tools (requires `attestation` feature)
    // =========================================================================

    /// Create a signed attestation document with subject, claims, and optional evidence.
    ///
    /// Requires the binary to be built with the `attestation` feature.
    #[tool(
        name = "jacs_attest_create",
        description = "Create a signed attestation document. Provide a JSON string with: subject (type, id, digests), claims (name, value, confidence, assuranceLevel), and optional evidence, derivation, and policyContext."
    )]
    pub async fn jacs_attest_create(
        &self,
        Parameters(params): Parameters<AttestCreateParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            match self.agent.create_attestation(&params.params_json) {
                Ok(result) => result,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "message": format!("Failed to create attestation: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }

    /// Verify an attestation document's cryptographic validity and optionally check evidence.
    ///
    /// Local tier: checks signature + hash only (fast).
    /// Full tier (full=true): also checks evidence digests, freshness, and derivation chain.
    #[tool(
        name = "jacs_attest_verify",
        description = "Verify an attestation document. Provide a document_key in 'jacsId:jacsVersion' format. Set full=true for evidence and chain verification."
    )]
    pub async fn jacs_attest_verify(
        &self,
        Parameters(params): Parameters<AttestVerifyParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            let result = if params.full {
                self.agent.verify_attestation_full(&params.document_key)
            } else {
                self.agent.verify_attestation(&params.document_key)
            };

            match result {
                Ok(json) => json,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "valid": false,
                        "message": format!("Failed to verify attestation: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "valid": false,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }

    /// Lift an existing signed document into an attestation with additional claims.
    ///
    /// Takes a signed JACS document and wraps it in an attestation that references
    /// the original document as its subject.
    #[tool(
        name = "jacs_attest_lift",
        description = "Lift an existing signed JACS document into an attestation. Provide the signed document JSON and a JSON array of claims."
    )]
    pub async fn jacs_attest_lift(
        &self,
        Parameters(params): Parameters<AttestLiftParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            match self
                .agent
                .lift_to_attestation(&params.signed_doc_json, &params.claims_json)
            {
                Ok(result) => result,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "message": format!("Failed to lift to attestation: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }
    /// Export a signed attestation as a DSSE (Dead Simple Signing Envelope) for
    /// in-toto/SLSA compatibility.
    #[tool(
        name = "jacs_attest_export_dsse",
        description = "Export an attestation as a DSSE envelope for in-toto/SLSA compatibility."
    )]
    pub async fn jacs_attest_export_dsse(
        &self,
        Parameters(params): Parameters<AttestExportDsseParams>,
    ) -> String {
        #[cfg(feature = "attestation")]
        {
            match self.agent.export_attestation_dsse(&params.attestation_json) {
                Ok(result) => result,
                Err(e) => {
                    let error = serde_json::json!({
                        "error": true,
                        "message": format!("Failed to export DSSE envelope: {}", e),
                    });
                    serde_json::to_string_pretty(&error).unwrap_or_else(|e| format!("Error: {}", e))
                }
            }
        }
        #[cfg(not(feature = "attestation"))]
        {
            let _ = params;
            serde_json::json!({
                "error": true,
                "message": "Attestation feature not available. Rebuild with --features attestation."
            })
            .to_string()
        }
    }

    // =========================================================================
    // Memory Tools
    // =========================================================================

    /// Save a memory as a cryptographically signed private agentstate document.
    ///
    /// Builds an agentstate document with `jacsAgentStateType: "memory"`,
    /// embeds the content inline, and signs it. No file path required.
    #[tool(
        name = "jacs_memory_save",
        description = "Save a memory as a cryptographically signed private document."
    )]
    pub async fn jacs_memory_save(
        &self,
        Parameters(params): Parameters<MemorySaveParams>,
    ) -> String {
        // Build agentstate document with inline content (no file path).
        let mut doc = match agentstate_crud::create_agentstate_with_content(
            "memory",
            &params.name,
            &params.content,
            "text/plain",
        ) {
            Ok(doc) => doc,
            Err(e) => {
                let result = MemorySaveResult {
                    success: false,
                    jacs_document_id: None,
                    name: params.name,
                    message: "Failed to create memory document".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Set optional fields.
        if let Some(desc) = &params.description {
            doc["jacsAgentStateDescription"] = serde_json::json!(desc);
        }

        if let Some(framework) = &params.framework {
            if let Err(e) = agentstate_crud::set_agentstate_framework(&mut doc, framework) {
                let result = MemorySaveResult {
                    success: false,
                    jacs_document_id: None,
                    name: params.name,
                    message: "Failed to set framework".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        if let Some(tags) = &params.tags {
            let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
            if let Err(e) = agentstate_crud::set_agentstate_tags(&mut doc, tag_refs) {
                let result = MemorySaveResult {
                    success: false,
                    jacs_document_id: None,
                    name: params.name,
                    message: "Failed to set tags".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        // Mark origin as "authored" and visibility as private.
        let _ = agentstate_crud::set_agentstate_origin(&mut doc, "authored", None);
        doc["jacsVisibility"] = serde_json::json!("private");

        // Sign and persist the document.
        let doc_string = doc.to_string();
        let result = match self.agent.create_document(
            &doc_string,
            None,       // custom_schema
            None,       // outputfilename
            true,       // no_save
            None,       // attachments
            Some(true), // embed
        ) {
            Ok(signed_doc_string) => {
                let doc_id = match extract_document_lookup_key_from_str(&signed_doc_string) {
                    Some(id) => id,
                    None => {
                        return serde_json::to_string_pretty(&MemorySaveResult {
                            success: false,
                            jacs_document_id: None,
                            name: params.name,
                            message: "Failed to determine the signed document ID".to_string(),
                            error: Some("DOCUMENT_ID_MISSING".to_string()),
                        })
                        .unwrap_or_else(|e| format!("Error: {}", e));
                    }
                };

                if let Err(e) =
                    self.agent
                        .save_signed_document(&signed_doc_string, None, None, None)
                {
                    return serde_json::to_string_pretty(&MemorySaveResult {
                        success: false,
                        jacs_document_id: Some(doc_id),
                        name: params.name,
                        message: "Failed to persist signed memory document".to_string(),
                        error: Some(e.to_string()),
                    })
                    .unwrap_or_else(|e| format!("Error: {}", e));
                }

                MemorySaveResult {
                    success: true,
                    jacs_document_id: Some(doc_id),
                    name: params.name,
                    message: "Memory saved successfully".to_string(),
                    error: None,
                }
            }
            Err(e) => MemorySaveResult {
                success: false,
                jacs_document_id: None,
                name: params.name,
                message: "Failed to sign memory document".to_string(),
                error: Some(e.to_string()),
            },
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        inject_meta(&serialized, None)
    }

    /// Search saved memories by query string and optional tag filter.
    ///
    /// Iterates over all stored documents, filters to memory-type agentstate
    /// documents that are not marked as removed, and matches the query against
    /// the name, content, and description fields.
    #[tool(
        name = "jacs_memory_recall",
        description = "Search saved memories by query string and optional tag filter."
    )]
    pub async fn jacs_memory_recall(
        &self,
        Parameters(params): Parameters<MemoryRecallParams>,
    ) -> String {
        let keys = match self.agent.list_document_keys() {
            Ok(keys) => keys,
            Err(e) => {
                let result = MemoryRecallResult {
                    success: false,
                    memories: Vec::new(),
                    total: 0,
                    message: "Failed to enumerate stored documents".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let limit = params.limit.unwrap_or(10) as usize;
        let query_lower = params.query.to_lowercase();
        let mut matched: Vec<(String, MemoryEntry)> = Vec::new();

        for key in keys {
            let doc_string = match self.agent.get_document_by_id(&key) {
                Ok(doc) => doc,
                Err(_) => continue,
            };
            let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
                Ok(doc) => doc,
                Err(_) => continue,
            };

            // Filter: must be agentstate with type "memory" and not removed.
            if doc.get("jacsType").and_then(|v| v.as_str()) != Some("agentstate") {
                continue;
            }
            if value_string(&doc, "jacsAgentStateType").as_deref() != Some("memory") {
                continue;
            }
            if doc
                .get("jacsAgentStateRemoved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }

            // Filter by tags if specified.
            let tags = value_string_vec(&doc, "jacsAgentStateTags");
            if let Some(filter_tags) = params.tags.as_ref() {
                let doc_tags = tags.clone().unwrap_or_default();
                if !filter_tags
                    .iter()
                    .all(|tag| doc_tags.iter().any(|item| item == tag))
                {
                    continue;
                }
            }

            // Match query against name, content, and description.
            let name = value_string(&doc, "jacsAgentStateName").unwrap_or_default();
            let content = extract_embedded_state_content(&doc).unwrap_or_default();
            let description = value_string(&doc, "jacsAgentStateDescription").unwrap_or_default();

            let matches = name.to_lowercase().contains(&query_lower)
                || content.to_lowercase().contains(&query_lower)
                || description.to_lowercase().contains(&query_lower);

            if !matches {
                continue;
            }

            let version_date = value_string(&doc, "jacsVersionDate").unwrap_or_default();
            let framework = value_string(&doc, "jacsAgentStateFramework");

            matched.push((
                version_date,
                MemoryEntry {
                    jacs_document_id: key,
                    name,
                    content: Some(content),
                    description: value_string(&doc, "jacsAgentStateDescription"),
                    tags: tags.filter(|items| !items.is_empty()),
                    framework,
                },
            ));
        }

        // Sort by version date descending (newest first).
        matched.sort_by(|a, b| b.0.cmp(&a.0));
        let total = matched.len();
        let memories: Vec<MemoryEntry> = matched
            .into_iter()
            .take(limit)
            .map(|(_, entry)| entry)
            .collect();

        let result = MemoryRecallResult {
            success: true,
            memories,
            total,
            message: format!(
                "Found {} memory/memories matching query '{}'",
                total, params.query
            ),
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        // Memory documents are always private by design.
        inject_meta(&serialized, None)
    }

    /// List all saved memory documents with optional filtering.
    ///
    /// Similar to `jacs_list_state` but locked to `state_type = "memory"`,
    /// with pagination support and removal filtering.
    #[tool(
        name = "jacs_memory_list",
        description = "List all saved memory documents with optional filtering and pagination."
    )]
    pub async fn jacs_memory_list(
        &self,
        Parameters(params): Parameters<MemoryListParams>,
    ) -> String {
        let keys = match self.agent.list_document_keys() {
            Ok(keys) => keys,
            Err(e) => {
                let result = MemoryListResult {
                    success: false,
                    memories: Vec::new(),
                    total: 0,
                    message: "Failed to enumerate stored documents".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let limit = params.limit.unwrap_or(20) as usize;
        let offset = params.offset.unwrap_or(0) as usize;
        let mut matched: Vec<(String, MemoryEntry)> = Vec::new();

        for key in keys {
            let doc_string = match self.agent.get_document_by_id(&key) {
                Ok(doc) => doc,
                Err(_) => continue,
            };
            let doc = match serde_json::from_str::<serde_json::Value>(&doc_string) {
                Ok(doc) => doc,
                Err(_) => continue,
            };

            // Filter: must be agentstate with type "memory" and not removed.
            if doc.get("jacsType").and_then(|v| v.as_str()) != Some("agentstate") {
                continue;
            }
            if value_string(&doc, "jacsAgentStateType").as_deref() != Some("memory") {
                continue;
            }
            if doc
                .get("jacsAgentStateRemoved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }

            // Filter by framework if specified.
            let framework = value_string(&doc, "jacsAgentStateFramework");
            if let Some(filter) = params.framework.as_deref()
                && framework.as_deref() != Some(filter)
            {
                continue;
            }

            // Filter by tags if specified.
            let tags = value_string_vec(&doc, "jacsAgentStateTags");
            if let Some(filter_tags) = params.tags.as_ref() {
                let doc_tags = tags.clone().unwrap_or_default();
                if !filter_tags
                    .iter()
                    .all(|tag| doc_tags.iter().any(|item| item == tag))
                {
                    continue;
                }
            }

            let name = value_string(&doc, "jacsAgentStateName").unwrap_or_else(|| key.clone());
            let content = extract_embedded_state_content(&doc);
            let description = value_string(&doc, "jacsAgentStateDescription");
            let version_date = value_string(&doc, "jacsVersionDate").unwrap_or_default();

            matched.push((
                version_date,
                MemoryEntry {
                    jacs_document_id: key,
                    name,
                    content,
                    description,
                    tags: tags.filter(|items| !items.is_empty()),
                    framework,
                },
            ));
        }

        // Sort by version date descending (newest first).
        matched.sort_by(|a, b| b.0.cmp(&a.0));
        let total = matched.len();
        let memories: Vec<MemoryEntry> = matched
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(_, entry)| entry)
            .collect();

        let result = MemoryListResult {
            success: true,
            memories,
            total,
            message: format!(
                "Listed {} memory document(s) (total: {}).",
                limit.min(total.saturating_sub(offset)),
                total
            ),
            error: None,
        };

        let serialized =
            serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
        // Memory documents are always private by design.
        inject_meta(&serialized, None)
    }

    /// Mark a memory document as removed (soft-delete).
    ///
    /// Loads the document, sets `jacsAgentStateRemoved: true`, and re-signs
    /// it as a new version. The provenance chain is preserved.
    #[tool(
        name = "jacs_memory_forget",
        description = "Mark a memory document as removed while preserving its provenance chain."
    )]
    pub async fn jacs_memory_forget(
        &self,
        Parameters(params): Parameters<MemoryForgetParams>,
    ) -> String {
        let existing_doc_string = match self.agent.get_document_by_id(&params.jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = MemoryForgetResult {
                    success: false,
                    jacs_document_id: params.jacs_id,
                    message: "Failed to load memory document".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut doc = match serde_json::from_str::<serde_json::Value>(&existing_doc_string) {
            Ok(v) => v,
            Err(e) => {
                let result = MemoryForgetResult {
                    success: false,
                    jacs_document_id: params.jacs_id,
                    message: "Memory document is not valid JSON".to_string(),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Verify this is actually a memory document.
        if value_string(&doc, "jacsAgentStateType").as_deref() != Some("memory") {
            let result = MemoryForgetResult {
                success: false,
                jacs_document_id: params.jacs_id,
                message: "Document is not a memory document".to_string(),
                error: Some("NOT_A_MEMORY".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Check if already removed to avoid creating redundant versions.
        if doc
            .get("jacsAgentStateRemoved")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let result = MemoryForgetResult {
                success: false,
                jacs_document_id: params.jacs_id,
                message: "Memory is already forgotten".to_string(),
                error: Some("ALREADY_REMOVED".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Mark as removed.
        doc["jacsAgentStateRemoved"] = serde_json::json!(true);

        match self
            .agent
            .update_document(&params.jacs_id, &doc.to_string(), None, None)
        {
            Ok(updated_doc_string) => {
                let new_id = serde_json::from_str::<serde_json::Value>(&updated_doc_string)
                    .ok()
                    .and_then(|v| extract_document_lookup_key(&v))
                    .unwrap_or_else(|| params.jacs_id.clone());

                let result = MemoryForgetResult {
                    success: true,
                    jacs_document_id: new_id,
                    message: format!(
                        "Memory '{}' has been forgotten (provenance preserved)",
                        params.jacs_id
                    ),
                    error: None,
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Err(e) => {
                let result = MemoryForgetResult {
                    success: false,
                    jacs_document_id: params.jacs_id,
                    message: "Failed to update and re-sign memory document".to_string(),
                    error: Some(e.to_string()),
                };
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
            }
        }
    }

    /// Update an existing memory with new content, name, or tags.
    ///
    /// Loads the memory document, applies the requested changes, and creates
    /// a new signed version linked to the previous version.
    #[tool(
        name = "jacs_memory_update",
        description = "Update an existing memory with new content, name, or tags."
    )]
    pub async fn jacs_memory_update(
        &self,
        Parameters(params): Parameters<MemoryUpdateParams>,
    ) -> String {
        let existing_doc_string = match self.agent.get_document_by_id(&params.jacs_id) {
            Ok(s) => s,
            Err(e) => {
                let result = MemoryUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    message: format!("Failed to load memory document '{}'", params.jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        let mut doc = match serde_json::from_str::<serde_json::Value>(&existing_doc_string) {
            Ok(v) => v,
            Err(e) => {
                let result = MemoryUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    message: format!("Memory document '{}' is not valid JSON", params.jacs_id),
                    error: Some(e.to_string()),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        };

        // Verify this is actually a memory document.
        if value_string(&doc, "jacsAgentStateType").as_deref() != Some("memory") {
            let result = MemoryUpdateResult {
                success: false,
                jacs_document_id: None,
                message: "Document is not a memory document".to_string(),
                error: Some("NOT_A_MEMORY".to_string()),
            };
            return serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| format!("Error: {}", e));
        }

        // Apply updates.
        if let Some(content) = params.content.as_deref() {
            update_embedded_state_content(&mut doc, content);
        }

        if let Some(name) = &params.name {
            doc["jacsAgentStateName"] = serde_json::json!(name);
        }

        if let Some(tags) = &params.tags {
            let tag_refs: Vec<&str> = tags.iter().map(|s| s.as_str()).collect();
            if let Err(e) = agentstate_crud::set_agentstate_tags(&mut doc, tag_refs) {
                let result = MemoryUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    message: "Failed to set tags".to_string(),
                    error: Some(e),
                };
                return serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
            }
        }

        match self
            .agent
            .update_document(&params.jacs_id, &doc.to_string(), None, None)
        {
            Ok(updated_doc_string) => {
                let version_id = serde_json::from_str::<serde_json::Value>(&updated_doc_string)
                    .ok()
                    .and_then(|v| extract_document_lookup_key(&v))
                    .unwrap_or_else(|| "unknown".to_string());

                let result = MemoryUpdateResult {
                    success: true,
                    jacs_document_id: Some(version_id),
                    message: format!("Memory '{}' updated successfully", params.jacs_id),
                    error: None,
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                inject_meta(&serialized, None)
            }
            Err(e) => {
                let result = MemoryUpdateResult {
                    success: false,
                    jacs_document_id: None,
                    message: format!("Failed to update and re-sign '{}'", params.jacs_id),
                    error: Some(e.to_string()),
                };
                let serialized = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("Error: {}", e));
                inject_meta(&serialized, None)
            }
        }
    }
}

// Implement the tool handler for the server.
//
// We intentionally do NOT use #[tool_handler(router = ...)] here because
// the macro generates list_tools/call_tool that expose ALL compiled-in tools,
// ignoring the runtime profile. Instead we manually implement list_tools to
// return only profile-filtered tools, and call_tool to reject tools outside
// the active profile before delegating to the router.
impl ServerHandler for JacsMcpServer {
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
                title: Some("JACS MCP Server".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                icons: None,
                website_url: Some("https://humanassisted.github.io/JACS/".to_string()),
            },
            instructions: Some(
                "This MCP server provides data provenance and cryptographic signing for \
                 agent state files and agent-to-agent messaging. \
                 \
                 Agent state tools: jacs_sign_state (sign files), jacs_verify_state \
                 (verify integrity), jacs_load_state (load with verification), \
                 jacs_update_state (update and re-sign), jacs_list_state (list signed docs), \
                 jacs_adopt_state (adopt external files). \
                 \
                 Memory tools: jacs_memory_save (save a memory), jacs_memory_recall \
                 (search memories by query), jacs_memory_list (list all memories), \
                 jacs_memory_forget (soft-delete a memory), jacs_memory_update \
                 (update an existing memory). \
                 \
                 Messaging tools: jacs_message_send (create and sign a message), \
                 jacs_message_update (update and re-sign a message), \
                 jacs_message_agree (co-sign/agree to a message), \
                 jacs_message_receive (verify and extract a received message). \
                 \
                 Agent management: jacs_create_agent (create new agent with keys), \
                 jacs_reencrypt_key (rotate private key password). \
                 \
                 A2A artifacts: jacs_wrap_a2a_artifact (sign artifact with provenance), \
                 jacs_verify_a2a_artifact (verify wrapped artifact), \
                 jacs_assess_a2a_agent (assess remote agent trust level). \
                 \
                 A2A discovery: jacs_export_agent_card (export Agent Card), \
                 jacs_generate_well_known (generate .well-known documents), \
                 jacs_export_agent (export full agent JSON). \
                 \
                 Trust store: jacs_trust_agent (add agent to trust store), \
                 jacs_untrust_agent (remove from trust store, requires JACS_MCP_ALLOW_UNTRUST=true), \
                 jacs_list_trusted_agents (list all trusted agent IDs), \
                 jacs_is_trusted (check if agent is trusted), \
                 jacs_get_trusted_agent (get trusted agent JSON). \
                 \
                 Attestation: jacs_attest_create (create signed attestation with claims), \
                 jacs_attest_verify (verify attestation, optionally with evidence checks), \
                 jacs_attest_lift (lift signed document into attestation), \
                 jacs_attest_export_dsse (export attestation as DSSE envelope). \
                 \
                 Security: jacs_audit (read-only security audit and health checks). \
                 \
                 Audit trail: jacs_audit_log (record events as signed audit entries), \
                 jacs_audit_query (search audit trail by action, target, time range), \
                 jacs_audit_export (export audit trail as signed bundle). \
                 \
                 Search: jacs_search (unified search across all signed documents)."
                    .to_string(),
            ),
        }
    }

    /// Return only the tools that belong to the active runtime profile.
    ///
    /// This replaces the `#[tool_handler]`-generated `list_tools` which would
    /// expose ALL compiled-in tools regardless of the profile.
    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::model::ErrorData> {
        Ok(rmcp::model::ListToolsResult {
            tools: self.active_tools(),
            meta: None,
            next_cursor: None,
        })
    }

    /// Dispatch a tool call, but only if the tool is in the active profile.
    ///
    /// Tools outside the active profile are rejected with a descriptive error
    /// rather than being silently executed.
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParam,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::model::ErrorData> {
        // Check that the requested tool is in the active profile.
        let active = self.active_tools();
        let tool_allowed = active.iter().any(|t| t.name == request.name);
        if !tool_allowed {
            return Err(rmcp::model::ErrorData::invalid_params(
                format!(
                    "Tool '{}' is not available in the '{}' profile. \
                     Use --profile full or set JACS_MCP_PROFILE=full to access all tools.",
                    request.name,
                    self.profile().as_str(),
                ),
                None,
            ));
        }
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }
}

#[cfg(test)]
#[allow(ambiguous_glob_imports)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_list_matches_compiled_features() {
        let tools = JacsMcpServer::tools();
        let names: Vec<&str> = tools.iter().map(|t| &*t.name).collect();

        // Total should match the compiled-in tool count
        assert_eq!(
            tools.len(),
            crate::tools::total_tool_count(),
            "tools() count should match total_tool_count()"
        );

        // Core tools are always present (core-tools is in default features)
        assert!(names.contains(&"jacs_sign_state"));
        assert!(names.contains(&"jacs_verify_state"));
        assert!(names.contains(&"jacs_load_state"));
        assert!(names.contains(&"jacs_update_state"));
        assert!(names.contains(&"jacs_list_state"));
        assert!(names.contains(&"jacs_adopt_state"));
        assert!(names.contains(&"jacs_create_agent"));
        assert!(names.contains(&"jacs_reencrypt_key"));
        assert!(names.contains(&"jacs_audit"));
        assert!(names.contains(&"jacs_audit_log"));
        assert!(names.contains(&"jacs_audit_query"));
        assert!(names.contains(&"jacs_audit_export"));
        assert!(names.contains(&"jacs_search"));
        assert!(names.contains(&"jacs_sign_document"));
        assert!(names.contains(&"jacs_verify_document"));
        assert!(names.contains(&"jacs_export_agent_card"));
        assert!(names.contains(&"jacs_generate_well_known"));
        assert!(names.contains(&"jacs_export_agent"));
        assert!(names.contains(&"jacs_trust_agent"));
        assert!(names.contains(&"jacs_untrust_agent"));
        assert!(names.contains(&"jacs_list_trusted_agents"));
        assert!(names.contains(&"jacs_is_trusted"));
        assert!(names.contains(&"jacs_get_trusted_agent"));
        assert!(names.contains(&"jacs_memory_save"));
        assert!(names.contains(&"jacs_memory_recall"));
        assert!(names.contains(&"jacs_memory_list"));
        assert!(names.contains(&"jacs_memory_forget"));
        assert!(names.contains(&"jacs_memory_update"));

        // Advanced tools conditionally present based on feature flags
        #[cfg(feature = "messaging-tools")]
        assert!(names.contains(&"jacs_message_send"));
        #[cfg(not(feature = "messaging-tools"))]
        assert!(!names.contains(&"jacs_message_send"));

        #[cfg(feature = "agreement-tools")]
        assert!(names.contains(&"jacs_create_agreement"));
        #[cfg(not(feature = "agreement-tools"))]
        assert!(!names.contains(&"jacs_create_agreement"));

        #[cfg(feature = "a2a-tools")]
        assert!(names.contains(&"jacs_wrap_a2a_artifact"));
        #[cfg(not(feature = "a2a-tools"))]
        assert!(!names.contains(&"jacs_wrap_a2a_artifact"));

        #[cfg(feature = "attestation-tools")]
        assert!(names.contains(&"jacs_attest_create"));
        #[cfg(not(feature = "attestation-tools"))]
        assert!(!names.contains(&"jacs_attest_create"));
    }

    #[test]
    fn test_jacs_audit_returns_risks_and_health_checks() {
        let json = jacs_binding_core::audit(None, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v.get("risks").is_some(),
            "jacs_audit response should have risks"
        );
        assert!(
            v.get("health_checks").is_some(),
            "jacs_audit response should have health_checks"
        );
    }

    #[test]
    fn test_sign_state_params_schema() {
        let schema = schemars::schema_for!(SignStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("state_type"));
        assert!(json.contains("name"));
        assert!(json.contains("embed"));
    }

    #[test]
    fn test_verify_state_params_schema() {
        let schema = schemars::schema_for!(VerifyStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("jacs_id"));
    }

    #[test]
    fn test_load_state_params_schema() {
        let schema = schemars::schema_for!(LoadStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("require_verified"));
    }

    #[test]
    fn test_update_state_params_schema() {
        let schema = schemars::schema_for!(UpdateStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("jacs_id"));
        assert!(json.contains("new_content"));
    }

    fn make_test_server() -> JacsMcpServer {
        JacsMcpServer::new(AgentWrapper::new())
    }

    #[test]
    fn test_verify_state_rejects_file_path_only() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_verify_state(Parameters(VerifyStateParams {
            file_path: Some("state.json".to_string()),
            jacs_id: None,
        })));
        assert!(response.contains("FILESYSTEM_ACCESS_DISABLED"));
        assert!(response.contains("file_path-based verification is disabled"));
    }

    #[test]
    fn test_load_state_rejects_file_path_only() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_load_state(Parameters(LoadStateParams {
            file_path: Some("state.json".to_string()),
            jacs_id: None,
            require_verified: Some(true),
        })));
        assert!(response.contains("FILESYSTEM_ACCESS_DISABLED"));
        assert!(response.contains("file_path-based loading is disabled"));
    }

    #[test]
    fn test_update_state_requires_jacs_id() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_update_state(Parameters(UpdateStateParams {
            file_path: "state.json".to_string(),
            jacs_id: None,
            new_content: Some("{\"k\":\"v\"}".to_string()),
        })));
        assert!(response.contains("FILESYSTEM_ACCESS_DISABLED"));
        assert!(response.contains("file_path-based updates are disabled"));
    }

    #[test]
    fn test_list_state_params_schema() {
        let schema = schemars::schema_for!(ListStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("state_type"));
        assert!(json.contains("framework"));
        assert!(json.contains("tags"));
    }

    #[test]
    fn test_adopt_state_params_schema() {
        let schema = schemars::schema_for!(AdoptStateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("file_path"));
        assert!(json.contains("state_type"));
        assert!(json.contains("name"));
        assert!(json.contains("source_url"));
    }

    #[test]
    fn test_create_agent_params_schema() {
        let schema = schemars::schema_for!(CreateAgentProgrammaticParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("name"));
        assert!(json.contains("password"));
        assert!(json.contains("algorithm"));
        assert!(json.contains("data_directory"));
        assert!(json.contains("key_directory"));
    }

    #[test]
    fn test_reencrypt_key_params_schema() {
        let schema = schemars::schema_for!(ReencryptKeyParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("old_password"));
        assert!(json.contains("new_password"));
    }

    #[test]
    fn test_validate_agent_id_valid() {
        assert!(validate_agent_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_agent_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
    }

    #[test]
    fn test_validate_agent_id_invalid() {
        assert!(validate_agent_id("").is_err());
        assert!(validate_agent_id("not-a-uuid").is_err());
        assert!(validate_agent_id("12345").is_err());
        assert!(validate_agent_id("550e8400-e29b-41d4-a716").is_err()); // Too short
    }

    #[test]
    fn test_extract_verify_a2a_valid_true() {
        assert!(extract_verify_a2a_valid(r#"{"valid":true}"#));
    }

    #[test]
    fn test_extract_verify_a2a_valid_missing_defaults_false() {
        assert!(!extract_verify_a2a_valid(r#"{"status":"ok"}"#));
    }

    #[test]
    fn test_extract_verify_a2a_valid_invalid_json_defaults_false() {
        assert!(!extract_verify_a2a_valid("not-json"));
    }

    #[test]
    fn test_is_registration_allowed_default() {
        // When env var is not set, should return false
        // SAFETY: This test runs in isolation and modifies test-specific env vars
        unsafe {
            std::env::remove_var("JACS_MCP_ALLOW_REGISTRATION");
        }
        assert!(!is_registration_allowed());
    }

    #[test]
    fn test_message_send_params_schema() {
        let schema = schemars::schema_for!(MessageSendParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("recipient_agent_id"));
        assert!(json.contains("content"));
        assert!(json.contains("content_type"));
    }

    #[test]
    fn test_message_update_params_schema() {
        let schema = schemars::schema_for!(MessageUpdateParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("jacs_id"));
        assert!(json.contains("content"));
        assert!(json.contains("content_type"));
    }

    #[test]
    fn test_message_agree_params_schema() {
        let schema = schemars::schema_for!(MessageAgreeParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_message"));
    }

    #[test]
    fn test_message_receive_params_schema() {
        let schema = schemars::schema_for!(MessageReceiveParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_message"));
    }

    #[test]
    fn test_format_iso8601() {
        // Unix epoch should produce 1970-01-01T00:00:00Z
        let epoch = std::time::UNIX_EPOCH;
        assert_eq!(format_iso8601(epoch), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_create_agreement_params_schema() {
        let schema = schemars::schema_for!(CreateAgreementParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("document"));
        assert!(json.contains("agent_ids"));
        assert!(json.contains("timeout"));
        assert!(json.contains("quorum"));
        assert!(json.contains("required_algorithms"));
        assert!(json.contains("minimum_strength"));
    }

    #[test]
    fn test_sign_agreement_params_schema() {
        let schema = schemars::schema_for!(SignAgreementParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_agreement"));
        assert!(json.contains("agreement_fieldname"));
    }

    #[test]
    fn test_check_agreement_params_schema() {
        let schema = schemars::schema_for!(CheckAgreementParams);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("signed_agreement"));
    }

    #[cfg(feature = "agreement-tools")]
    #[test]
    fn test_tool_list_includes_agreement_tools() {
        // Verify the 3 agreement tools are registered when agreement-tools is enabled
        let tools = JacsMcpServer::tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            names.contains(&"jacs_create_agreement"),
            "Missing jacs_create_agreement"
        );
        assert!(
            names.contains(&"jacs_sign_agreement"),
            "Missing jacs_sign_agreement"
        );
        assert!(
            names.contains(&"jacs_check_agreement"),
            "Missing jacs_check_agreement"
        );
    }

    // =========================================================================
    // Security: Path traversal prevention in sign_state / adopt_state
    // =========================================================================

    #[test]
    fn test_sign_state_rejects_absolute_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "/etc/passwd".to_string(),
            state_type: "memory".to_string(),
            name: "traversal-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
        assert!(
            response.contains("\"success\": false"),
            "Expected success: false in: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_rejects_parent_traversal() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "data/../../../etc/shadow".to_string(),
            state_type: "hook".to_string(),
            name: "traversal-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: Some(true),
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_rejects_windows_drive_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            state_type: "config".to_string(),
            name: "traversal-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_adopt_state_rejects_absolute_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_adopt_state(Parameters(AdoptStateParams {
            file_path: "/etc/shadow".to_string(),
            state_type: "skill".to_string(),
            name: "traversal-test".to_string(),
            source_url: None,
            description: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
        assert!(
            response.contains("\"success\": false"),
            "Expected success: false in: {}",
            response
        );
    }

    #[test]
    fn test_adopt_state_rejects_parent_traversal() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_adopt_state(Parameters(AdoptStateParams {
            file_path: "skills/../../etc/passwd".to_string(),
            state_type: "skill".to_string(),
            name: "traversal-test".to_string(),
            source_url: Some("https://example.com".to_string()),
            description: None,
        })));
        assert!(
            response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Expected PATH_TRAVERSAL_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_allows_safe_relative_path() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        // This should NOT be blocked by path validation (it will fail later
        // because the file doesn't exist, but NOT with PATH_TRAVERSAL_BLOCKED)
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "jacs_data/my-state.json".to_string(),
            state_type: "memory".to_string(),
            name: "safe-path-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            !response.contains("PATH_TRAVERSAL_BLOCKED"),
            "Safe relative path should not be blocked: {}",
            response
        );
    }

    #[test]
    fn test_sign_state_rejects_path_outside_default_state_roots() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_sign_state(Parameters(SignStateParams {
            file_path: "notes/secret.txt".to_string(),
            state_type: "memory".to_string(),
            name: "blocked-root-test".to_string(),
            description: None,
            framework: None,
            tags: None,
            embed: None,
        })));
        assert!(
            response.contains("STATE_FILE_ACCESS_BLOCKED"),
            "Expected STATE_FILE_ACCESS_BLOCKED in: {}",
            response
        );
    }

    #[test]
    fn test_adopt_state_rejects_path_outside_default_state_roots() {
        let server = make_test_server();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let response = rt.block_on(server.jacs_adopt_state(Parameters(AdoptStateParams {
            file_path: "notes/secret.txt".to_string(),
            state_type: "skill".to_string(),
            name: "blocked-root-test".to_string(),
            source_url: Some("https://example.com/secret.txt".to_string()),
            description: None,
        })));
        assert!(
            response.contains("STATE_FILE_ACCESS_BLOCKED"),
            "Expected STATE_FILE_ACCESS_BLOCKED in: {}",
            response
        );
    }
}
