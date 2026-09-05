//! Native entry point for the portable Agreement v3 protocol.
//!
//! All protocol logic lives in `jacs-core`; keeping this module as a pure
//! re-export prevents native SDK behavior from drifting from WASM.

pub use jacs_core::agreements::v3::*;
