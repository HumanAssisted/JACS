//! JACS email signing and verification module.
//!
//! Provides functions for signing emails with JACS detached signatures
//! and verifying those signatures. The email-specific code computes
//! hashes and compares them -- it never touches cryptography directly
//! (that is handled by the JACS layer).

pub mod attachment;
pub mod canonicalize;
pub mod error;
pub mod sign;
pub mod types;
pub mod verify;

// Re-export all public types from submodules.
pub use attachment::*;
pub use canonicalize::*;
pub use error::*;
pub use sign::*;
pub use types::*;
pub use verify::*;
