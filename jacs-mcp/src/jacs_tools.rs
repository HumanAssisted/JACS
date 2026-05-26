//! JACS MCP tools for data provenance and cryptographic signing.
//!
//! This module provides MCP tools for signing, verification, agreements,
//! A2A interoperability, agent management, and trust store management.
//!
//! ## Tech Debt (Issue 017)
//!
//! This file contains all tool handler implementations in a single monolith.
//! TASK_038 split **type definitions and tool registration**
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
use jacs::validation::require_relative_path_safe;
use jacs_binding_core::AgentWrapper;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo, Tool, ToolsCapability};
use rmcp::{ServerHandler, tool, tool_router};
use sha2::{Digest, Sha256};

use crate::tools::*;
use std::sync::Arc;

// =============================================================================
// Helper Functions
// =============================================================================

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

fn validate_optional_relative_path(label: &str, path: Option<&String>) -> Result<(), String> {
    if let Some(path) = path {
        require_relative_path_safe(path)
            .map_err(|e| format!("{} path validation failed: {}", label, e))?;
    }
    Ok(())
}

#[cfg(not(feature = "agreement-tools"))]
fn agreement_v2_document_tools_unavailable() -> String {
    let result = AgreementV2DocumentResult {
        success: false,
        agreement: None,
        error: Some(
            "Agreement v2 tools are not compiled. Rebuild jacs-mcp with --features agreement-tools or --features full-tools."
                .to_string(),
        ),
    };
    let serialized =
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
    inject_meta(&serialized, None)
}

#[cfg(not(feature = "agreement-tools"))]
fn agreement_v2_value_tools_unavailable() -> String {
    let result = AgreementV2ValueResult {
        success: false,
        result: None,
        error: Some(
            "Agreement v2 tools are not compiled. Rebuild jacs-mcp with --features agreement-tools or --features full-tools."
                .to_string(),
        ),
    };
    let serialized =
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
    inject_meta(&serialized, None)
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

fn value_string(doc: &serde_json::Value, field: &str) -> Option<String> {
    doc.get(field).and_then(|v| v.as_str()).map(str::to_string)
}

/// Extract verification validity from `verify_a2a_artifact` details JSON.
/// Defaults to `false` on malformed/missing fields to avoid optimistic trust.
fn extract_verify_a2a_valid(details_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(details_json)
        .ok()
        .and_then(|v| v.get("valid").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

// =============================================================================
// MCP Server
// =============================================================================

/// JACS MCP Server providing tools for data provenance, cryptographic signing,
/// agreements, A2A interoperability, and trust store management.
#[derive(Clone)]
#[allow(dead_code)]
pub struct JacsMcpServer {
    /// The local agent identity.
    agent: Arc<AgentWrapper>,
    /// Unified document service resolved from the loaded agent config.
    document_service: Option<Arc<dyn DocumentService>>,
    /// Optional `SimpleAgent` used by the inline-text and media tools
    /// (PRD §4.1, §4.2). Loaded at server construction from `JACS_CONFIG`
    /// when available; absent for unit-test constructors that only exercise
    /// tool registration/metadata.
    simple_agent: Option<Arc<jacs::simple::SimpleAgent>>,
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

        // PRD §4.1, §4.2: the inline-text and media tools call into `SimpleAgent`,
        // a higher-level facade over the raw Agent. We materialise one here from
        // the same config the AgentWrapper already loaded, so the new tools share
        // the server's identity rather than spinning up an ephemeral throwaway.
        let simple_agent = match Self::load_simple_agent_from_env() {
            Ok(Some(sa)) => Some(Arc::new(sa)),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(
                    "SimpleAgent unavailable for inline-text / media tools: {}. \
                     jacs_sign_text / jacs_verify_text / jacs_sign_image / \
                     jacs_verify_image / jacs_extract_media_signature will return \
                     a clear error envelope when called.",
                    err
                );
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
            simple_agent,
            tool_router: Self::tool_router(),
            registration_allowed,
            untrust_allowed,
            profile,
        }
    }

    /// Try to load a `SimpleAgent` from the `JACS_CONFIG` env var.
    ///
    /// Returns `Ok(None)` if `JACS_CONFIG` isn't set (tests that exercise
    /// only tool metadata don't need an agent). Returns `Err(_)` when the
    /// env var is set but loading fails — propagated to the caller for
    /// logging.
    fn load_simple_agent_from_env() -> anyhow::Result<Option<jacs::simple::SimpleAgent>> {
        let cfg_path = match std::env::var("JACS_CONFIG") {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let resolved = if std::path::Path::new(&cfg_path).is_absolute() {
            std::path::PathBuf::from(&cfg_path)
        } else {
            std::env::current_dir()?.join(&cfg_path)
        };
        if !resolved.exists() {
            return Ok(None);
        }
        let agent = jacs::simple::SimpleAgent::load(Some(&resolved.to_string_lossy()), None)
            .map_err(|e| {
                anyhow::anyhow!("SimpleAgent::load({}) failed: {}", resolved.display(), e)
            })?;
        Ok(Some(agent))
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

    fn with_agent<T>(
        &self,
        f: impl FnOnce(&jacs::agent::Agent) -> Result<T, jacs::JacsError>,
    ) -> Result<T, String> {
        let agent_arc = self.agent.inner_arc();
        let agent = agent_arc
            .lock()
            .map_err(|e| format!("Failed to acquire agent lock: {}", e))?;
        f(&agent).map_err(|e| e.to_string())
    }

    fn with_agent_mut<T>(
        &self,
        f: impl FnOnce(&mut jacs::agent::Agent) -> Result<T, jacs::JacsError>,
    ) -> Result<T, String> {
        let agent_arc = self.agent.inner_arc();
        let mut agent = agent_arc
            .lock()
            .map_err(|e| format!("Failed to acquire agent lock: {}", e))?;
        f(&mut agent).map_err(|e| e.to_string())
    }
}

// Implement the tool router for the server
#[tool_router]
impl JacsMcpServer {
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

    /// Rotate the agent's cryptographic keys.
    ///
    /// Generates a new keypair, signs a transition proof with the old key,
    /// re-signs the agent document and config with the new key.
    #[tool(
        name = "jacs_rotate_keys",
        description = "Rotate the agent's cryptographic keys with optional algorithm change."
    )]
    pub async fn jacs_rotate_keys(
        &self,
        Parameters(params): Parameters<key::RotateKeysParams>,
    ) -> String {
        let result = match self.agent.rotate_keys(params.algorithm.as_deref()) {
            Ok(json_str) => {
                let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();
                key::RotateKeysResult {
                    success: true,
                    jacs_id: parsed["jacs_id"].as_str().map(String::from),
                    old_version: parsed["old_version"].as_str().map(String::from),
                    new_version: parsed["new_version"].as_str().map(String::from),
                    new_public_key_hash: parsed["new_public_key_hash"].as_str().map(String::from),
                    has_transition_proof: parsed["transition_proof"].is_string(),
                    message: "Key rotation successful".to_string(),
                    error: None,
                }
            }
            Err(e) => key::RotateKeysResult {
                success: false,
                jacs_id: None,
                old_version: None,
                new_version: None,
                new_public_key_hash: None,
                has_transition_proof: false,
                message: "Key rotation failed".to_string(),
                error: Some(e.to_string()),
            },
        };

        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
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
                let name = value_string(doc, "jacsName")
                    .or_else(|| value_string(doc, "title"))
                    .or_else(|| value_string(doc, "name"));
                let snippet = value_string(doc, "jacsDescription")
                    .or_else(|| value_string(doc, "description"))
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

    /// Create a standalone agreement v2 artifact.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_create_agreement_v2",
            description = "Create a standalone JACS agreement v2 document for verifiable consent to terms."
        )
    )]
    pub async fn jacs_create_agreement_v2(
        &self,
        Parameters(params): Parameters<CreateAgreementV2Params>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_document_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let input_json = match serde_json::to_string(&params.input) {
                Ok(json) => json,
                Err(e) => {
                    let result = AgreementV2DocumentResult {
                        success: false,
                        agreement: None,
                        error: Some(format!("Failed to serialize agreement v2 input: {}", e)),
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
            };

            let result = match self.agent.create_agreement_v2_json(&input_json) {
                Ok(agreement) => AgreementV2DocumentResult {
                    success: true,
                    agreement: Some(agreement),
                    error: None,
                },
                Err(e) => AgreementV2DocumentResult {
                    success: false,
                    agreement: None,
                    error: Some(format!("Failed to create agreement v2: {}", e)),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
    }

    /// Apply a typed mutation to a standalone agreement v2 artifact.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_apply_agreement_v2",
            description = "Apply an agreement v2 mutation and emit a successor version."
        )
    )]
    pub async fn jacs_apply_agreement_v2(
        &self,
        Parameters(params): Parameters<ApplyAgreementV2Params>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_document_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let mutation_json = match serde_json::to_string(&params.mutation) {
                Ok(json) => json,
                Err(e) => {
                    let result = AgreementV2DocumentResult {
                        success: false,
                        agreement: None,
                        error: Some(format!("Failed to serialize agreement v2 mutation: {}", e)),
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
            };

            let result = match self
                .agent
                .apply_agreement_v2_json(&params.agreement, &mutation_json)
            {
                Ok(agreement) => AgreementV2DocumentResult {
                    success: true,
                    agreement: Some(agreement),
                    error: None,
                },
                Err(e) => AgreementV2DocumentResult {
                    success: false,
                    agreement: None,
                    error: Some(format!("Failed to update agreement v2: {}", e)),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
    }

    /// Add this agent's signer, witness, or notary agreement signature.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_sign_agreement_v2",
            description = "Add this agent's signer, witness, or notary signature to an agreement v2 document."
        )
    )]
    pub async fn jacs_sign_agreement_v2(
        &self,
        Parameters(params): Parameters<SignAgreementV2Params>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_document_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let role = params.role.unwrap_or_else(|| "signer".to_string());
            let result = match self.agent.sign_agreement_v2_json(&params.agreement, &role) {
                Ok(agreement) => AgreementV2DocumentResult {
                    success: true,
                    agreement: Some(agreement),
                    error: None,
                },
                Err(e) => AgreementV2DocumentResult {
                    success: false,
                    agreement: None,
                    error: Some(format!("Failed to sign agreement v2: {}", e)),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
    }

    /// Verify agreement v2 hash, status, transcript, and signature invariants.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_verify_agreement_v2",
            description = "Verify a standalone JACS agreement v2 document."
        )
    )]
    pub async fn jacs_verify_agreement_v2(
        &self,
        Parameters(params): Parameters<VerifyAgreementV2Params>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_value_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let result = match self.agent.verify_agreement_v2_json(&params.agreement) {
                Ok(report_json) => AgreementV2ValueResult {
                    success: true,
                    result: serde_json::from_str(&report_json).ok(),
                    error: None,
                },
                Err(e) => AgreementV2ValueResult {
                    success: false,
                    result: None,
                    error: Some(format!("Failed to verify agreement v2: {}", e)),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
    }

    /// Detect whether two agreement v2 branches are transcript-only mergeable.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_detect_agreement_v2_branch_conflict",
            description = "Analyze two agreement v2 successor versions for branch conflicts."
        )
    )]
    pub async fn jacs_detect_agreement_v2_branch_conflict(
        &self,
        Parameters(params): Parameters<DetectAgreementV2BranchConflictParams>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_value_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let result = match self.agent.detect_agreement_v2_branch_conflict_json(
                &params.base,
                &params.left,
                &params.right,
            ) {
                Ok(analysis_json) => AgreementV2ValueResult {
                    success: true,
                    result: serde_json::from_str(&analysis_json).ok(),
                    error: None,
                },
                Err(e) => AgreementV2ValueResult {
                    success: false,
                    result: None,
                    error: Some(format!(
                        "Failed to detect agreement v2 branch conflict: {}",
                        e
                    )),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
    }

    /// Auto-merge two transcript-only agreement v2 branches.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_merge_agreement_v2_transcript_branches",
            description = "Auto-merge two transcript-only agreement v2 branches."
        )
    )]
    pub async fn jacs_merge_agreement_v2_transcript_branches(
        &self,
        Parameters(params): Parameters<MergeAgreementV2TranscriptBranchesParams>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_document_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let result = match self.agent.merge_agreement_v2_transcript_branches_json(
                &params.base,
                &params.left,
                &params.right,
            ) {
                Ok(agreement) => AgreementV2DocumentResult {
                    success: true,
                    agreement: Some(agreement),
                    error: None,
                },
                Err(e) => AgreementV2DocumentResult {
                    success: false,
                    agreement: None,
                    error: Some(format!(
                        "Failed to merge agreement v2 transcript branches: {}",
                        e
                    )),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
    }

    /// Resolve a conflicting agreement v2 branch with an explicit mutation.
    #[cfg_attr(
        feature = "agreement-tools",
        tool(
            name = "jacs_resolve_agreement_v2_branch_conflict",
            description = "Resolve an agreement v2 branch conflict by applying an explicit mutation."
        )
    )]
    pub async fn jacs_resolve_agreement_v2_branch_conflict(
        &self,
        Parameters(params): Parameters<ResolveAgreementV2BranchConflictParams>,
    ) -> String {
        #[cfg(not(feature = "agreement-tools"))]
        {
            let _ = params;
            agreement_v2_document_tools_unavailable()
        }
        #[cfg(feature = "agreement-tools")]
        {
            let mutation_json = match serde_json::to_string(&params.mutation) {
                Ok(json) => json,
                Err(e) => {
                    let result = AgreementV2DocumentResult {
                        success: false,
                        agreement: None,
                        error: Some(format!(
                            "Failed to serialize agreement v2 resolution mutation: {}",
                            e
                        )),
                    };
                    return serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|e| format!("Error: {}", e));
                }
            };

            let result = match self.agent.resolve_agreement_v2_branch_conflict_json(
                &params.base,
                &params.previous,
                &params.side_branch,
                &mutation_json,
            ) {
                Ok(agreement) => AgreementV2DocumentResult {
                    success: true,
                    agreement: Some(agreement),
                    error: None,
                },
                Err(e) => AgreementV2DocumentResult {
                    success: false,
                    agreement: None,
                    error: Some(format!(
                        "Failed to resolve agreement v2 branch conflict: {}",
                        e
                    )),
                },
            };
            let serialized =
                serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e));
            inject_meta(&serialized, None)
        }
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

    /// Export this agent's W3C did:wba identifier.
    #[tool(
        name = "jacs_w3c_export_did",
        description = "Export this agent's did:wba identifier for W3C AI Agent Protocol interop."
    )]
    pub async fn jacs_w3c_export_did(
        &self,
        Parameters(params): Parameters<W3cOriginParams>,
    ) -> String {
        let result = match self.with_agent(|agent| {
            jacs::w3c::export_did_identifier_with_options(
                agent,
                jacs::w3c::W3cDidOptions {
                    origin: params.origin,
                },
            )
        }) {
            Ok(did) => W3cDidResult {
                success: true,
                did: Some(did),
                message: "W3C DID exported successfully".to_string(),
                error: None,
            },
            Err(e) => W3cDidResult {
                success: false,
                did: None,
                message: "Failed to export W3C DID".to_string(),
                error: Some(e),
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Export this agent's W3C DID document.
    #[tool(
        name = "jacs_w3c_export_did_document",
        description = "Export this agent's W3C did:wba DID document."
    )]
    pub async fn jacs_w3c_export_did_document(
        &self,
        Parameters(params): Parameters<W3cOriginParams>,
    ) -> String {
        let result = match self.with_agent(|agent| {
            jacs::w3c::export_did_document(
                agent,
                jacs::w3c::W3cDidOptions {
                    origin: params.origin,
                },
            )
        }) {
            Ok(document) => W3cJsonDocumentResult {
                success: true,
                document: Some(document),
                message: "W3C DID document exported successfully".to_string(),
                error: None,
            },
            Err(e) => W3cJsonDocumentResult {
                success: false,
                document: None,
                message: "Failed to export W3C DID document".to_string(),
                error: Some(e),
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Export this agent's W3C agent description.
    #[tool(
        name = "jacs_w3c_export_agent_description",
        description = "Export this agent's W3C agent description document."
    )]
    pub async fn jacs_w3c_export_agent_description(
        &self,
        Parameters(params): Parameters<W3cOriginParams>,
    ) -> String {
        let result = match self.with_agent(|agent| {
            jacs::w3c::export_agent_description(
                agent,
                jacs::w3c::W3cDidOptions {
                    origin: params.origin,
                },
            )
        }) {
            Ok(document) => W3cJsonDocumentResult {
                success: true,
                document: Some(document),
                message: "W3C agent description exported successfully".to_string(),
                error: None,
            },
            Err(e) => W3cJsonDocumentResult {
                success: false,
                document: None,
                message: "Failed to export W3C agent description".to_string(),
                error: Some(e),
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Generate W3C well-known discovery documents.
    #[tool(
        name = "jacs_w3c_generate_well_known",
        description = "Generate W3C well-known discovery documents keyed by path."
    )]
    pub async fn jacs_w3c_generate_well_known(
        &self,
        Parameters(params): Parameters<W3cOriginParams>,
    ) -> String {
        let result = match self.with_agent(|agent| {
            jacs::w3c::generate_w3c_well_known_documents(
                agent,
                jacs::w3c::W3cDidOptions {
                    origin: params.origin,
                },
            )
        }) {
            Ok(documents) => {
                let count = documents.len();
                let mut by_path = serde_json::Map::new();
                for (path, document) in documents {
                    by_path.insert(path, document);
                }
                W3cWellKnownResult {
                    success: true,
                    documents: Some(serde_json::Value::Object(by_path)),
                    count,
                    message: format!("{} W3C discovery document(s) generated", count),
                    error: None,
                }
            }
            Err(e) => W3cWellKnownResult {
                success: false,
                documents: None,
                count: 0,
                message: "Failed to generate W3C discovery documents".to_string(),
                error: Some(e),
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Create a request-bound DID authentication proof.
    #[tool(
        name = "jacs_w3c_sign_request",
        description = "Create a request-bound DID authentication proof for a concrete HTTP request."
    )]
    pub async fn jacs_w3c_sign_request(
        &self,
        Parameters(params): Parameters<W3cSignRequestParams>,
    ) -> String {
        let result = match self.with_agent_mut(|agent| {
            jacs::w3c::build_request_proof(
                agent,
                jacs::w3c::W3cRequestProofParams {
                    method: params.method,
                    url: params.url,
                    body: params.body,
                    nonce: params.nonce,
                    created: params.created,
                    origin: params.origin,
                },
            )
        }) {
            Ok(proof) => W3cRequestProofResult {
                success: true,
                proof: Some(proof),
                message: "W3C request proof signed successfully".to_string(),
                error: None,
            },
            Err(e) => W3cRequestProofResult {
                success: false,
                proof: None,
                message: "Failed to sign W3C request proof".to_string(),
                error: Some(e),
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Verify a request-bound DID authentication proof.
    #[tool(
        name = "jacs_w3c_verify_request",
        description = "Verify a request-bound DID authentication proof against a resolved DID document."
    )]
    pub async fn jacs_w3c_verify_request(
        &self,
        Parameters(params): Parameters<W3cVerifyRequestParams>,
    ) -> String {
        let verifier = jacs::get_empty_agent();
        let result = match jacs::w3c::verify_request_proof_for_request(
            &verifier,
            &params.proof_json,
            &params.did_document_json,
            params.body.as_deref(),
            params.max_age_seconds.unwrap_or(300),
            params.method.as_deref(),
            params.url.as_deref(),
        ) {
            Ok(verification) => W3cVerifyRequestResult {
                success: true,
                verification: Some(verification),
                message: "W3C request proof verified successfully".to_string(),
                error: None,
            },
            Err(e) => W3cVerifyRequestResult {
                success: false,
                verification: None,
                message: "Failed to verify W3C request proof".to_string(),
                error: Some(e.to_string()),
            },
        };
        serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
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

    /// Sign a text/markdown file in place by appending an inline JACS signature
    /// block (PRD §4.1).
    #[tool(
        name = "jacs_sign_text",
        description = "Sign a text/markdown file in place with an inline JACS signature block."
    )]
    pub async fn jacs_sign_text(&self, Parameters(params): Parameters<SignTextParams>) -> String {
        // PRD §4.2.6: every wave-3 file-path handler MUST run through the
        // six-layer path policy (base-dir confinement, absolute/traversal
        // rejection, leaf-symlink rejection, output-overwrite policy, backup
        // placement). `require_relative_path_safe` alone covers only
        // structural checks — it lets a bare relative name escape the
        // configured `JACS_MCP_BASE_DIR` because resolution then falls back
        // to the server CWD. See R-003.
        let resolved_input = match crate::path_policy::resolve_input_path(&params.file_path) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return inline_text_error_envelope(
                    &params.file_path,
                    "Path validation failed",
                    format!("PATH_POLICY_BLOCKED: {}", e),
                );
            }
        };

        let simple_agent = match self.simple_agent.as_ref() {
            Some(sa) => Arc::clone(sa),
            None => {
                return inline_text_error_envelope(
                    &params.file_path,
                    "MCP server has no SimpleAgent loaded",
                    "MCP_SERVER_NOT_INITIALIZED: set JACS_CONFIG to a valid agent config"
                        .to_string(),
                );
            }
        };

        let opts = jacs::simple::SignTextOptions {
            backup: !params.no_backup.unwrap_or(false),
            allow_duplicate: false,
            unsafe_bak_mode: None,
        };

        let file_path = resolved_input;
        let result = tokio::task::spawn_blocking(move || {
            jacs::simple::advanced::sign_text_file(&simple_agent, &file_path, opts)
        })
        .await;

        let outcome = match result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return inline_text_error_envelope(
                    &params.file_path,
                    "Failed to sign text file",
                    e.to_string(),
                );
            }
            Err(join_err) => {
                return inline_text_error_envelope(
                    &params.file_path,
                    "Sign worker panicked",
                    join_err.to_string(),
                );
            }
        };

        let signer_id = self
            .simple_agent
            .as_ref()
            .and_then(|sa| sa.key_id().ok())
            .filter(|s| !s.is_empty());
        let result = SignTextResult {
            success: true,
            file_path: outcome.path,
            signers_added: outcome.signers_added,
            backup_path: outcome.backup_path,
            message: if outcome.signers_added == 0 {
                "File already signed by this agent (idempotent no-op)".to_string()
            } else {
                "Inline JACS signature appended".to_string()
            },
            error: None,
        };
        // Override signer_id from header (the wrapper outcome doesn't carry it).
        let mut value = serde_json::to_value(&result).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(sid) = signer_id
            && let Some(obj) = value.as_object_mut()
        {
            obj.insert("signer_id".to_string(), serde_json::Value::String(sid));
        }
        serde_json::to_string_pretty(&value).unwrap_or_else(|e| format!("Error: {}", e))
    }

    /// Verify inline JACS signatures in a text/markdown file (PRD §4.1, C1).
    #[tool(
        name = "jacs_verify_text",
        description = "Verify inline JACS signatures in a text/markdown file. Permissive by default; pass strict:true for hard-fail on missing signature."
    )]
    pub async fn jacs_verify_text(
        &self,
        Parameters(params): Parameters<VerifyTextParams>,
    ) -> String {
        // PRD §4.2.6 / R-003: full six-layer path policy.
        let resolved_input = match crate::path_policy::resolve_input_path(&params.file_path) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return verify_text_error_envelope(
                    &params.file_path,
                    "Path validation failed",
                    format!("PATH_POLICY_BLOCKED: {}", e),
                );
            }
        };

        let simple_agent = match self.simple_agent.as_ref() {
            Some(sa) => Arc::clone(sa),
            None => {
                return verify_text_error_envelope(
                    &params.file_path,
                    "MCP server has no SimpleAgent loaded",
                    "MCP_SERVER_NOT_INITIALIZED".to_string(),
                );
            }
        };

        let strict = params.strict.unwrap_or(false);
        let opts = jacs::inline::VerifyOptions {
            strict,
            key_dir: params.key_dir.as_deref().map(std::path::PathBuf::from),
        };

        let file_path = resolved_input;
        let result = tokio::task::spawn_blocking(move || {
            jacs::simple::advanced::verify_text_file(&simple_agent, &file_path, opts)
        })
        .await;

        match result {
            Ok(Ok(jacs::inline::VerifyTextResult::Signed { signatures })) => {
                let entries: Vec<SignatureEntry> = signatures
                    .into_iter()
                    .map(|s| SignatureEntry {
                        signer_id: s.signer_id,
                        algorithm: s.algorithm,
                        timestamp: s.timestamp,
                        status: signature_status_string(&s.status),
                    })
                    .collect();
                let envelope = VerifyTextResult {
                    success: true,
                    status: "signed".to_string(),
                    message: format!("Verified {} signature block(s)", entries.len()),
                    signatures: entries,
                    error: None,
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Ok(jacs::inline::VerifyTextResult::MissingSignature)) => {
                // Permissive mode (strict=false) only — strict mode returns Err below.
                let envelope = VerifyTextResult {
                    success: true,
                    status: "missing_signature".to_string(),
                    signatures: vec![],
                    message: "No JACS signature block found in file".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Ok(jacs::inline::VerifyTextResult::Malformed(reason))) => {
                let envelope = VerifyTextResult {
                    success: false,
                    status: "malformed".to_string(),
                    signatures: vec![],
                    message: "Signature block is malformed".to_string(),
                    error: Some(reason),
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Err(jacs::error::JacsError::MissingSignature(p))) if strict => {
                let envelope = VerifyTextResult {
                    success: false,
                    status: "missing_signature".to_string(),
                    signatures: vec![],
                    message: "Strict verification: no JACS signature block found".to_string(),
                    error: Some(format!("no JACS signature found in {}", p)),
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Err(e)) => {
                verify_text_error_envelope(&params.file_path, "Verification failed", e.to_string())
            }
            Err(join_err) => verify_text_error_envelope(
                &params.file_path,
                "Verify worker panicked",
                join_err.to_string(),
            ),
        }
    }

    /// Sign an image (PNG/JPEG/WebP) by embedding a JACS signature
    /// (PRD §4.2).
    #[tool(
        name = "jacs_sign_image",
        description = "Sign a PNG/JPEG/WebP image by embedding a JACS signature in format-native metadata. Robust mode (PNG/JPEG only) additionally embeds into the LSB channel."
    )]
    pub async fn jacs_sign_image(&self, Parameters(params): Parameters<SignImageParams>) -> String {
        // PRD §4.2.6 / R-003: input must exist inside base_dir; output must
        // either be inside base_dir and not already exist, OR be allowed via
        // JACS_MCP_OVERWRITE_OK=1 / refuse_overwrite=false (in-place sign).
        let resolved_input = match crate::path_policy::resolve_input_path(&params.input_path) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return sign_image_error_envelope(
                    &params.output_path,
                    "Path validation failed",
                    format!("PATH_POLICY_BLOCKED: {}", e),
                );
            }
        };
        // For output, use resolve_output_path when it differs from input (a
        // distinct write target is governed by overwrite policy). When equal,
        // the operation is in-place and resolve_input_path applies.
        let resolved_output = if params.input_path == params.output_path {
            resolved_input.clone()
        } else {
            match crate::path_policy::resolve_output_path(&params.output_path) {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(e) => {
                    return sign_image_error_envelope(
                        &params.output_path,
                        "Path validation failed",
                        format!("PATH_POLICY_BLOCKED: {}", e),
                    );
                }
            }
        };

        let simple_agent = match self.simple_agent.as_ref() {
            Some(sa) => Arc::clone(sa),
            None => {
                return sign_image_error_envelope(
                    &params.output_path,
                    "MCP server has no SimpleAgent loaded",
                    "MCP_SERVER_NOT_INITIALIZED".to_string(),
                );
            }
        };

        let opts = jacs::simple::SignImageOptions {
            robust: params.robust.unwrap_or(false),
            format_hint: params.format.clone(),
            refuse_overwrite: params.refuse_overwrite.unwrap_or(false),
            // PRD §4.2.4a: leave automatic backup decision to the lower layer
            // (default true on in-place, false on different out path).
            backup: true,
            unsafe_bak_mode: None,
        };

        let in_path = resolved_input;
        let out_path = resolved_output;
        let result = tokio::task::spawn_blocking(move || {
            jacs::simple::advanced::sign_image(&simple_agent, &in_path, &out_path, opts)
        })
        .await;

        match result {
            Ok(Ok(signed)) => {
                let envelope = SignImageResult {
                    success: true,
                    out_path: signed.out_path,
                    signer_id: Some(signed.signer_id),
                    format: Some(signed.format),
                    robust: signed.robust,
                    message: "Image signed".to_string(),
                    error: None,
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Err(e)) => sign_image_error_envelope(
                &params.output_path,
                "Failed to sign image",
                e.to_string(),
            ),
            Err(join_err) => sign_image_error_envelope(
                &params.output_path,
                "Sign-image worker panicked",
                join_err.to_string(),
            ),
        }
    }

    /// Verify an embedded JACS signature in an image (PRD §4.2, C1).
    #[tool(
        name = "jacs_verify_image",
        description = "Verify an embedded JACS signature in a PNG/JPEG/WebP image. Permissive by default; pass strict:true for hard-fail on missing signature."
    )]
    pub async fn jacs_verify_image(
        &self,
        Parameters(params): Parameters<VerifyImageParams>,
    ) -> String {
        // PRD §4.2.6 / R-003.
        let resolved_input = match crate::path_policy::resolve_input_path(&params.file_path) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return verify_image_error_envelope(
                    &params.file_path,
                    "Path validation failed",
                    format!("PATH_POLICY_BLOCKED: {}", e),
                );
            }
        };

        let simple_agent = match self.simple_agent.as_ref() {
            Some(sa) => Arc::clone(sa),
            None => {
                return verify_image_error_envelope(
                    &params.file_path,
                    "MCP server has no SimpleAgent loaded",
                    "MCP_SERVER_NOT_INITIALIZED".to_string(),
                );
            }
        };

        let strict = params.strict.unwrap_or(false);
        let opts = jacs::simple::VerifyImageOptions {
            base: jacs::inline::VerifyOptions {
                strict,
                key_dir: params.key_dir.as_deref().map(std::path::PathBuf::from),
            },
            scan_robust: params.robust.unwrap_or(false),
        };

        let file_path = resolved_input;
        let result = tokio::task::spawn_blocking(move || {
            jacs::simple::advanced::verify_image(&simple_agent, &file_path, opts)
        })
        .await;

        match result {
            Ok(Ok(media)) => {
                let status = media_status_string(&media.status);
                let success = matches!(
                    media.status,
                    jacs::simple::MediaVerifyStatus::Valid
                        | jacs::simple::MediaVerifyStatus::MissingSignature
                );
                let message = match &media.status {
                    jacs::simple::MediaVerifyStatus::Valid => "Image signature valid".to_string(),
                    jacs::simple::MediaVerifyStatus::InvalidSignature => {
                        "Image signature is invalid".to_string()
                    }
                    jacs::simple::MediaVerifyStatus::HashMismatch => {
                        "Image hash mismatch (content was modified)".to_string()
                    }
                    jacs::simple::MediaVerifyStatus::MissingSignature => {
                        "No JACS signature found in image".to_string()
                    }
                    jacs::simple::MediaVerifyStatus::KeyNotFound => {
                        "Signer's public key could not be resolved".to_string()
                    }
                    jacs::simple::MediaVerifyStatus::UnsupportedFormat => {
                        "Unsupported image format".to_string()
                    }
                    jacs::simple::MediaVerifyStatus::Malformed(s) => {
                        format!("Malformed signature: {}", s)
                    }
                };
                let error = match &media.status {
                    jacs::simple::MediaVerifyStatus::Malformed(s) => Some(s.clone()),
                    _ => None,
                };
                let envelope = VerifyImageResult {
                    success,
                    status,
                    signer_id: media.signer_id,
                    algorithm: media.algorithm,
                    format: media.format,
                    embedding_channels: media.embedding_channels,
                    message,
                    error,
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Err(jacs::error::JacsError::MissingSignature(p))) if strict => {
                let envelope = VerifyImageResult {
                    success: false,
                    status: "missing_signature".to_string(),
                    signer_id: None,
                    algorithm: None,
                    format: None,
                    embedding_channels: None,
                    message: "Strict verification: no JACS signature found in image".to_string(),
                    error: Some(format!("no JACS signature found in {}", p)),
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Err(e)) => {
                verify_image_error_envelope(&params.file_path, "Verification failed", e.to_string())
            }
            Err(join_err) => verify_image_error_envelope(
                &params.file_path,
                "Verify-image worker panicked",
                join_err.to_string(),
            ),
        }
    }

    /// Extract the JACS signature payload from a signed image (PRD §3.2).
    #[tool(
        name = "jacs_extract_media_signature",
        description = "Extract the JACS signature payload embedded in a PNG/JPEG/WebP image. Returns decoded JSON by default; pass raw_payload:true for the base64url wire form."
    )]
    pub async fn jacs_extract_media_signature(
        &self,
        Parameters(params): Parameters<ExtractMediaSignatureParams>,
    ) -> String {
        // PRD §4.2.6 / R-003.
        let resolved_input = match crate::path_policy::resolve_input_path(&params.file_path) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return extract_media_error_envelope(
                    "Path validation failed",
                    format!("PATH_POLICY_BLOCKED: {}", e),
                );
            }
        };

        let raw = params.raw_payload.unwrap_or(false);
        // R-011: scan_robust opt-in for the extract verb (parity with verify).
        let extract_opts = jacs::simple::types::ExtractMediaOptions {
            scan_robust: params.robust.unwrap_or(false),
        };
        let file_path = resolved_input;
        let result = tokio::task::spawn_blocking(move || {
            if raw {
                jacs::simple::advanced::extract_media_signature_raw_with_options(
                    &file_path,
                    extract_opts,
                )
            } else {
                jacs::simple::advanced::extract_media_signature_with_options(
                    &file_path,
                    extract_opts,
                )
            }
        })
        .await;

        match result {
            Ok(Ok(payload)) => {
                let envelope = ExtractMediaSignatureResult {
                    success: true,
                    present: payload.is_some(),
                    payload: payload.clone(),
                    message: if payload.is_some() {
                        "Extracted JACS signature payload".to_string()
                    } else {
                        "No JACS signature payload found in image".to_string()
                    },
                    error: None,
                };
                serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| format!("Error: {}", e))
            }
            Ok(Err(e)) => extract_media_error_envelope("Extraction failed", e.to_string()),
            Err(join_err) => {
                extract_media_error_envelope("Extract worker panicked", join_err.to_string())
            }
        }
    }
}

// =============================================================================
// Helpers for the inline-text + media handlers (Task 09).
// =============================================================================

fn signature_status_string(s: &jacs::inline::SignatureStatus) -> String {
    match s {
        jacs::inline::SignatureStatus::Valid => "valid".to_string(),
        jacs::inline::SignatureStatus::InvalidSignature => "invalid_signature".to_string(),
        jacs::inline::SignatureStatus::HashMismatch => "hash_mismatch".to_string(),
        jacs::inline::SignatureStatus::KeyNotFound => "key_not_found".to_string(),
        jacs::inline::SignatureStatus::UnsupportedAlgorithm => "unsupported_algorithm".to_string(),
        jacs::inline::SignatureStatus::Malformed(_) => "malformed".to_string(),
    }
}

fn media_status_string(s: &jacs::simple::MediaVerifyStatus) -> String {
    match s {
        jacs::simple::MediaVerifyStatus::Valid => "valid".to_string(),
        jacs::simple::MediaVerifyStatus::InvalidSignature => "invalid_signature".to_string(),
        jacs::simple::MediaVerifyStatus::HashMismatch => "hash_mismatch".to_string(),
        jacs::simple::MediaVerifyStatus::MissingSignature => "missing_signature".to_string(),
        jacs::simple::MediaVerifyStatus::KeyNotFound => "key_not_found".to_string(),
        jacs::simple::MediaVerifyStatus::UnsupportedFormat => "unsupported_format".to_string(),
        jacs::simple::MediaVerifyStatus::Malformed(_) => "malformed".to_string(),
    }
}

fn inline_text_error_envelope(file_path: &str, message: &str, error: String) -> String {
    let result = SignTextResult {
        success: false,
        file_path: file_path.to_string(),
        signers_added: 0,
        backup_path: None,
        message: message.to_string(),
        error: Some(error),
    };
    serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
}

fn verify_text_error_envelope(_file_path: &str, message: &str, error: String) -> String {
    let result = VerifyTextResult {
        success: false,
        status: "error".to_string(),
        signatures: vec![],
        message: message.to_string(),
        error: Some(error),
    };
    serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
}

fn sign_image_error_envelope(out_path: &str, message: &str, error: String) -> String {
    let result = SignImageResult {
        success: false,
        out_path: out_path.to_string(),
        signer_id: None,
        format: None,
        robust: false,
        message: message.to_string(),
        error: Some(error),
    };
    serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
}

fn verify_image_error_envelope(_file_path: &str, message: &str, error: String) -> String {
    let result = VerifyImageResult {
        success: false,
        status: "error".to_string(),
        signer_id: None,
        algorithm: None,
        format: None,
        embedding_channels: None,
        message: message.to_string(),
        error: Some(error),
    };
    serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
}

fn extract_media_error_envelope(message: &str, error: String) -> String {
    let result = ExtractMediaSignatureResult {
        success: false,
        present: false,
        payload: None,
        message: message.to_string(),
        error: Some(error),
    };
    serde_json::to_string_pretty(&result).unwrap_or_else(|e| format!("Error: {}", e))
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
        let mut info = ServerInfo::default();
        let mut capabilities = ServerCapabilities::default();
        capabilities.tools = Some(ToolsCapability {
            list_changed: Some(false),
        });
        info.capabilities = capabilities;
        info.server_info = Implementation::new("jacs-mcp", env!("CARGO_PKG_VERSION"))
            .with_title("JACS MCP Server")
            .with_website_url("https://humanassisted.github.io/JACS/");
        info.instructions = Some(
            "This MCP server provides data provenance and cryptographic signing for \
                 signed documents, agreements, A2A artifacts, agents, and configuration. \
                 \
                 Document signing: jacs_sign_document (sign JSON content), \
                 jacs_verify_document (verify a signed JACS document). \
                 \
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
                 W3C interop: jacs_w3c_export_did (export did:wba identifier), \
                 jacs_w3c_export_did_document (export DID document), \
                 jacs_w3c_export_agent_description (export agent description), \
                 jacs_w3c_generate_well_known (generate W3C discovery documents), \
                 jacs_w3c_sign_request (create request-bound DID proof), \
                 jacs_w3c_verify_request (verify request-bound DID proof). \
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
                 Search: jacs_search (unified search across all signed documents). \
                 \
                 Inline text and media: jacs_sign_text (sign a markdown/text file in place), \
                 jacs_verify_text (verify inline JACS signatures), jacs_sign_image \
                 (sign PNG/JPEG/WebP by embedding metadata), jacs_verify_image \
                 (verify image signature), jacs_extract_media_signature (dump embedded JACS payload)."
                .to_string(),
        );
        info
    }

    /// Return only the tools that belong to the active runtime profile.
    ///
    /// This replaces the `#[tool_handler]`-generated `list_tools` which would
    /// expose ALL compiled-in tools regardless of the profile.
    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
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
        request: rmcp::model::CallToolRequestParams,
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

        #[cfg(feature = "document-tools")]
        {
            assert!(names.contains(&"jacs_create_agent"));
            assert!(names.contains(&"jacs_sign_document"));
            assert!(names.contains(&"jacs_verify_document"));
        }

        #[cfg(feature = "key-tools")]
        {
            assert!(names.contains(&"jacs_reencrypt_key"));
            assert!(names.contains(&"jacs_export_agent_card"));
            assert!(names.contains(&"jacs_generate_well_known"));
            assert!(names.contains(&"jacs_export_agent"));
            assert!(names.contains(&"jacs_w3c_export_did"));
            assert!(names.contains(&"jacs_w3c_generate_well_known"));
        }

        #[cfg(feature = "search-tools")]
        assert!(names.contains(&"jacs_search"));

        #[cfg(feature = "trust-tools")]
        {
            assert!(names.contains(&"jacs_trust_agent"));
            assert!(names.contains(&"jacs_untrust_agent"));
            assert!(names.contains(&"jacs_list_trusted_agents"));
            assert!(names.contains(&"jacs_is_trusted"));
            assert!(names.contains(&"jacs_get_trusted_agent"));
        }

        // Retired schema-specific families are not exposed.
        assert!(!names.iter().any(|name| name.starts_with("jacs_message_")));
        assert!(!names.iter().any(|name| name.starts_with("jacs_memory_")));
        assert!(!names.iter().any(|name| name.starts_with("jacs_audit")));

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
}
