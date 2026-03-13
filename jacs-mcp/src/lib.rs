pub mod config;
#[cfg(feature = "mcp")]
pub mod contract;
pub mod jacs_tools;
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
#[cfg(feature = "mcp")]
pub use crate::server::serve_stdio;
