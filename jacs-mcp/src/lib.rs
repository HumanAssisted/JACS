//! JACS Model Context Protocol (MCP) server.
//!
//! This crate provides an MCP server that exposes JACS operations as tools
//! for AI assistants and LLM workflows.
//!
//! # Tool Profiles
//!
//! `verify-only` is the default and exposes no signing, trust mutation, key
//! mutation, agent creation, or legacy Agreement signing. The only other
//! recognized process profiles are `local-sign`, `trust-admin`, and bounded
//! `legacy-core`. `local-sign` additionally requires an explicitly selected,
//! authenticated local config. It authorizes a closed JSON/Agreement tool set
//! as that agent, not per-action human approval. Administrative profiles remain
//! unavailable; a profile enum alone never loads or authorizes a signer.
//!
//! # Profile Resolution
//!
//! 1. `--profile <name>` CLI flag (highest priority)
//! 2. `JACS_MCP_PROFILE` environment variable
//! 3. Default: `verify-only`
//!
//! # Usage
//!
//! ```bash
//! # Start with verification-only tools (default)
//! jacs mcp
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
#[cfg(feature = "mcp")]
mod local_signing;
pub mod path_policy;
#[cfg(feature = "mcp")]
pub mod profile;
#[cfg(feature = "mcp")]
pub mod server;
#[cfg(feature = "mcp")]
pub mod tools;

pub use crate::config::{
    load_agent_from_config_env, load_agent_from_config_env_with_info, load_agent_from_config_path,
    load_agent_from_config_path_with_info, load_public_agent_from_config_env_with_info,
    load_public_agent_from_config_path_with_info,
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
