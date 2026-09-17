//! Focused local MCP adapter and native encrypted-file custody.
//!
//! Cryptography is delegated to `jacs-core`. The default MCP profile only
//! verifies caller-supplied public evidence. Local signing requires an explicit
//! vault path and a password supplied by the embedding application.

#[cfg(feature = "mcp")]
pub mod contract;
#[cfg(feature = "mcp")]
mod server;
pub mod vault;

#[cfg(feature = "mcp")]
pub use server::{JacsMcpServer, Profile, serve_stdio};
