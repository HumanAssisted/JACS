//! JACS Model Context Protocol (MCP) server.
//!
//! This crate provides an MCP server that exposes JACS operations as tools
//! for AI assistants and LLM workflows.
//!
//! # Tool Profiles
//!
//! Tools are organized into families and exposed via runtime profiles:
//!
//! **Core profile** (default) -- 7 tool families for everyday signing and verification:
//! - `state` -- Agent state management (quickstart, load, create)
//! - `document` -- Document CRUD (create, sign, verify, update)
//! - `trust` -- Trust store management (add, remove, list trusted agents)
//! - `audit` -- Security audit and diagnostics
//! - `memory` -- Agent memory and local state
//! - `search` -- Document search and discovery
//! - `key` -- Key management and export
//!
//! **Full profile** -- Core + 4 advanced families:
//! - `agreements` -- Multi-agent agreement signing with quorum
//! - `messaging` -- Signed message exchange
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
pub mod jacs_tools;
pub mod profile;
#[cfg(feature = "mcp")]
pub mod server;
pub mod tools;

pub use crate::config::{load_agent_from_config_env, load_agent_from_config_path};
#[cfg(feature = "mcp")]
pub use crate::contract::{
    JacsMcpContractSnapshot, JacsMcpServerMetadata, JacsMcpToolContract,
    canonical_contract_snapshot,
};
pub use crate::jacs_tools::JacsMcpServer;
pub use crate::profile::Profile;
#[cfg(feature = "mcp")]
pub use crate::server::serve_stdio;
