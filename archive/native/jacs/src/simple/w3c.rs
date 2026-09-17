use crate::error::JacsError;
use crate::simple::SimpleAgent;
use crate::w3c::auth::{
    W3cRequestProofParams, build_request_proof, verify_request_proof_for_request,
};
use crate::w3c::did_wba::{
    W3cDidOptions, export_did_document, export_did_identifier, export_did_identifier_with_options,
};
use crate::w3c::{export_agent_description, generate_w3c_well_known_documents};
use serde_json::Value;

pub fn export_w3c_did_identifier(agent: &SimpleAgent) -> Result<String, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    export_did_identifier(&inner)
}

pub fn export_w3c_did_identifier_with_origin(
    agent: &SimpleAgent,
    origin: Option<&str>,
) -> Result<String, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    export_did_identifier_with_options(
        &inner,
        W3cDidOptions {
            origin: origin.map(str::to_string),
        },
    )
}

pub fn export_w3c_did_document(
    agent: &SimpleAgent,
    origin: Option<&str>,
) -> Result<Value, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    export_did_document(
        &inner,
        W3cDidOptions {
            origin: origin.map(str::to_string),
        },
    )
}

pub fn export_w3c_agent_description(
    agent: &SimpleAgent,
    origin: Option<&str>,
) -> Result<Value, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    export_agent_description(
        &inner,
        W3cDidOptions {
            origin: origin.map(str::to_string),
        },
    )
}

pub fn generate_w3c_well_known(
    agent: &SimpleAgent,
    origin: Option<&str>,
) -> Result<Vec<(String, Value)>, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    generate_w3c_well_known_documents(
        &inner,
        W3cDidOptions {
            origin: origin.map(str::to_string),
        },
    )
}

pub fn sign_w3c_request(
    agent: &SimpleAgent,
    params: W3cRequestProofParams,
) -> Result<Value, JacsError> {
    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    build_request_proof(&mut inner, params)
}

pub fn verify_w3c_request(
    agent: &SimpleAgent,
    proof_json: &str,
    did_document_json: &str,
    body: Option<&str>,
    max_age_seconds: u64,
    expected_method: Option<&str>,
    expected_url: Option<&str>,
) -> Result<Value, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    verify_request_proof_for_request(
        &inner,
        proof_json,
        did_document_json,
        body,
        max_age_seconds,
        expected_method,
        expected_url,
    )
}
