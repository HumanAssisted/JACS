//! Experimental W3C AI Agent Protocol interoperability helpers.
//!
//! This module is intentionally isolated from the core JACS document model.
//! JACS identifiers and signatures remain canonical inside JACS; DID and
//! JSON-LD documents are exported views for W3C-facing discovery and auth.

pub mod agent_description;
pub mod auth;
pub mod did_wba;
pub mod discovery;

pub use agent_description::{export_agent_description, export_agent_description_with_options};
pub use auth::{
    W3cRequestProofParams, build_request_proof, verify_request_proof,
    verify_request_proof_for_request, verify_request_proof_value,
    verify_request_proof_value_for_request,
};
pub use did_wba::{
    W3cDidOptions, W3cDidParts, default_agent_description_path, did_document_path,
    export_did_document, export_did_identifier, export_did_identifier_with_options,
};
pub use discovery::generate_w3c_well_known_documents;
