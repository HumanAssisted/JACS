use crate::observability::metrics::{increment_counter, record_histogram};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Record an agent operation with both metrics and structured logging
pub fn record_agent_operation(operation: &str, agent_id: &str, success: bool, duration_ms: u64) {
    let mut tags = HashMap::new();
    tags.insert("operation".to_string(), operation.to_string());
    tags.insert("agent_id".to_string(), agent_id.to_string());
    tags.insert("success".to_string(), success.to_string());

    // Metrics
    increment_counter("jacs_agent_operations_total", 1, Some(tags.clone()));
    record_histogram(
        "jacs_agent_operation_duration_ms",
        duration_ms as f64,
        Some(tags),
    );

    // Structured logging
    if success {
        info!(
            operation = operation,
            agent_id = agent_id,
            duration_ms = duration_ms,
            "Agent operation completed successfully"
        );
    } else {
        error!(
            operation = operation,
            agent_id = agent_id,
            duration_ms = duration_ms,
            "Agent operation failed"
        );
    }
}

/// Record document validation with metrics and logging
pub fn record_document_validation(doc_id: &str, schema_version: &str, valid: bool) {
    let mut tags = HashMap::new();
    tags.insert("schema_version".to_string(), schema_version.to_string());
    tags.insert("valid".to_string(), valid.to_string());

    // Metrics
    increment_counter("jacs_document_validations_total", 1, Some(tags));

    // Structured logging
    if valid {
        debug!(
            document_id = doc_id,
            schema_version = schema_version,
            "Document validation passed"
        );
    } else {
        warn!(
            document_id = doc_id,
            schema_version = schema_version,
            "Document validation failed"
        );
    }
}

/// Record signature verification with metrics and logging
pub fn record_signature_verification(agent_id: &str, success: bool, algorithm: &str) {
    let mut tags = HashMap::new();
    tags.insert("algorithm".to_string(), algorithm.to_string());
    tags.insert("success".to_string(), success.to_string());

    // Metrics
    increment_counter("jacs_signature_verifications_total", 1, Some(tags));

    // Structured logging
    if success {
        debug!(
            agent_id = agent_id,
            algorithm = algorithm,
            "Signature verification successful"
        );
    } else {
        error!(
            agent_id = agent_id,
            algorithm = algorithm,
            "Signature verification failed"
        );
    }
}

/// Record network communication metrics
pub fn record_network_request(endpoint: &str, method: &str, status_code: u16, duration_ms: u64) {
    let mut tags = HashMap::new();
    tags.insert("endpoint".to_string(), endpoint.to_string());
    tags.insert("method".to_string(), method.to_string());
    tags.insert("status_code".to_string(), status_code.to_string());

    increment_counter("jacs_network_requests_total", 1, Some(tags.clone()));
    record_histogram(
        "jacs_network_request_duration_ms",
        duration_ms as f64,
        Some(tags),
    );

    info!(
        endpoint = endpoint,
        method = method,
        status_code = status_code,
        duration_ms = duration_ms,
        "Network request completed"
    );
}

/// Record memory usage metrics
pub fn record_memory_usage(component: &str, bytes_used: u64) {
    let mut tags = HashMap::new();
    tags.insert("component".to_string(), component.to_string());

    crate::observability::metrics::set_gauge(
        "jacs_memory_usage_bytes",
        bytes_used as f64,
        Some(tags),
    );

    debug!(
        component = component,
        bytes_used = bytes_used,
        "Memory usage recorded"
    );
}
