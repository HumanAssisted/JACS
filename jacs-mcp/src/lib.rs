//! JACS Model Context Protocol (MCP) server.
//!
//! This crate provides an MCP server that exposes JACS operations as tools
//! for AI assistants and LLM workflows.
//!
//! # Tool Profiles
//!
//! Tools are organized into families and exposed via runtime profiles:
//!
//! **Core profile** (default) -- tool families for everyday signing and verification:
//! - `document` -- Document CRUD (create, sign, verify, update)
//! - `trust` -- Trust store management (add, remove, list trusted agents)
//! - `search` -- Document search and discovery
//! - `key` -- Key management and export
//!
//! **Full profile** -- Core + advanced families:
//! - `agreements` -- Multi-agent agreement signing with quorum
//! - `a2a` -- Agent-to-Agent protocol tools
//! - `attestation` -- Evidence-based attestation and DSSE
//!
//! # Profile Resolution
//!
//! 1. `--profile <name>` CLI flag (highest priority)
//! 2. `JACS_MCP_PROFILE` environment variable
//! 3. Default: `core`
//!
//! # Usage
//!
//! ```bash
//! # Start with core tools (default)
//! jacs mcp
//!
//! # Start with all tools
//! jacs mcp --profile full
//!
//! # Via environment variable
//! JACS_MCP_PROFILE=full jacs mcp
//! ```

#![allow(ambiguous_glob_imports)]

pub mod config;
#[cfg(feature = "mcp")]
pub mod contract;
// `jacs_tools` is the rmcp-tool-routed handler surface; it requires the
// `mcp` feature (rmcp / tokio). Bindings that only need `path_policy`
// (PRD §4.2.6) build with `default-features = false` — see jacspy/jacsnpm.
#[cfg(feature = "mcp")]
pub mod jacs_tools;
pub mod path_policy;
#[cfg(feature = "mcp")]
pub mod profile;
#[cfg(feature = "mcp")]
pub mod server;
#[cfg(feature = "mcp")]
pub mod tools;

pub use crate::config::{
    load_agent_from_config_env, load_agent_from_config_env_with_info, load_agent_from_config_path,
    load_agent_from_config_path_with_info,
};
#[cfg(feature = "mcp")]
pub use crate::contract::{
    JacsMcpContractSnapshot, JacsMcpServerMetadata, JacsMcpToolContract,
    canonical_contract_snapshot,
};
#[cfg(feature = "mcp")]
pub use crate::jacs_tools::JacsMcpServer;
#[cfg(feature = "mcp")]
pub use crate::profile::Profile;
#[cfg(feature = "mcp")]
pub use crate::server::serve_stdio;
