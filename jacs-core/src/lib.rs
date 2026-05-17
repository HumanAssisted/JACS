//! JACS portable protocol layer.
//!
//! `jacs-core` holds the protocol bits of JACS that must compile for both
//! native and `wasm32-unknown-unknown` targets: canonical JSON, signing
//! algorithm dispatch, encrypted-key envelopes, embedded schemas, and
//! agreement payload logic. It performs **no I/O**, opens no files, makes
//! no network calls, and pulls in no native-only crates. See
//! `docs/jacs/JACS_WASM_PRD.md` for the full split rationale.

pub mod canonical;
pub mod envelope;
pub mod errors;
pub mod schema;

pub use errors::CoreError;
