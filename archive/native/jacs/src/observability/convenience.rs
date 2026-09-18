use crate::error::JacsError;
use crate::observability::metrics::{increment_counter, record_histogram};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Stable event name for security-sensitive verification and policy outcomes.
pub const SECURITY_OUTCOME_EVENT: &str = "security_outcome";

/// Stable, low-cardinality counter for security-sensitive outcomes.
pub const SECURITY_OUTCOME_METRIC: &str = "jacs_security_outcomes_total";

/// Verification surface that produced a [`SecurityOutcome`].
///
/// This is an enum rather than a free-form label so callers cannot accidentally
/// create an unbounded metric label set.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SecuritySource {
    Config,
    RequestAuth,
    ResponseEnvelope,
    SignedEvent,
    Replay,
    EncryptedKey,
    InlineText,
    InlineImage,
}

impl SecuritySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::RequestAuth => "request_auth",
            Self::ResponseEnvelope => "response_envelope",
            Self::SignedEvent => "signed_event",
            Self::Replay => "replay",
            Self::EncryptedKey => "encrypted_key",
            Self::InlineText => "inline_text",
            Self::InlineImage => "inline_image",
        }
    }
}

/// Stable verification/policy outcome taxonomy shared by Rust and bindings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SecurityOutcome {
    Valid,
    BadSignature,
    UnknownKey,
    Stale,
    Duplicate,
    StoreUnavailable,
    ParserRejected,
    KdfPolicyRejected,
    Unverified,
    PolicyRejected,
}

impl SecurityOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::BadSignature => "bad_signature",
            Self::UnknownKey => "unknown_key",
            Self::Stale => "stale",
            Self::Duplicate => "duplicate",
            Self::StoreUnavailable => "store_unavailable",
            Self::ParserRejected => "parser_rejected",
            Self::KdfPolicyRejected => "kdf_policy_rejected",
            Self::Unverified => "unverified",
            Self::PolicyRejected => "policy_rejected",
        }
    }

    /// Stable error-kind value for callers that map events back to binding
    /// errors. Successful verification deliberately uses `none`.
    pub const fn error_kind(self) -> &'static str {
        match self {
            Self::Valid => "none",
            Self::BadSignature => "signature_verification_failed",
            Self::UnknownKey => "signer_unknown",
            Self::Stale => "proof_stale",
            Self::Duplicate => "replay_detected",
            Self::StoreUnavailable => "replay_store_unavailable",
            Self::ParserRejected => "malformed_input",
            Self::KdfPolicyRejected => "resource_policy_rejected",
            Self::Unverified => "verification_not_established",
            Self::PolicyRejected => "policy_rejected",
        }
    }

    const fn is_warning(self) -> bool {
        !matches!(self, Self::Valid)
    }
}

/// Policy mode in force for a security-sensitive operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SecurityPolicy {
    Strict,
    Permissive,
}

impl SecurityPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Permissive => "permissive",
        }
    }
}

/// Map a typed JACS failure to the portable security outcome taxonomy.
///
/// The few legacy failures that do not yet have dedicated variants are
/// classified by durable phrases, but their raw text is never emitted.
pub fn security_outcome_for_error(error: &JacsError) -> SecurityOutcome {
    match error {
        JacsError::SignerUnknown { .. }
        | JacsError::AgentNotTrusted { .. }
        | JacsError::KeyNotFound { .. } => SecurityOutcome::UnknownKey,
        JacsError::SignatureInvalid { .. } | JacsError::HashMismatch { .. } => {
            SecurityOutcome::BadSignature
        }
        JacsError::SignatureVerificationFailed { reason } | JacsError::CryptoError(reason) => {
            security_outcome_from_text(reason, SecurityOutcome::BadSignature)
        }
        JacsError::Internal { message } => {
            security_outcome_from_text(message, SecurityOutcome::PolicyRejected)
        }
        JacsError::StorageError(message) => {
            security_outcome_from_text(message, SecurityOutcome::StoreUnavailable)
        }
        JacsError::DatabaseError { reason, .. } => {
            security_outcome_from_text(reason, SecurityOutcome::StoreUnavailable)
        }
        JacsError::DocumentMalformed { .. }
        | JacsError::ValidationError(_)
        | JacsError::SchemaError(_) => SecurityOutcome::ParserRejected,
        JacsError::MissingSignature(_) => SecurityOutcome::Unverified,
        JacsError::KeyDecryptionFailed { reason } => {
            security_outcome_from_text(reason, SecurityOutcome::PolicyRejected)
        }
        _ => SecurityOutcome::PolicyRejected,
    }
}

fn security_outcome_from_text(text: &str, fallback: SecurityOutcome) -> SecurityOutcome {
    let text = text.to_ascii_lowercase();
    if text.contains("replay store")
        || text.contains("replay backend")
        || text.contains("shared replay store")
    {
        SecurityOutcome::StoreUnavailable
    } else if text.contains("replay attack") || text.contains("nonce has already been used") {
        SecurityOutcome::Duplicate
    } else if text.contains("expired")
        || text.contains("stale")
        || text.contains("too old")
        || text.contains("too far in the future")
    {
        SecurityOutcome::Stale
    } else if text.contains("argon2id parameter policy rejected") {
        SecurityOutcome::KdfPolicyRejected
    } else if text.contains("signature verification")
        || text.contains("invalid base64 signature")
        || text.contains("cryptographic operation failed")
    {
        SecurityOutcome::BadSignature
    } else {
        fallback
    }
}

/// Emit the portable security outcome event and increment its counter.
///
/// Metric labels are intentionally limited to enum-backed values. Optional
/// identifiers appear only in logs and are accepted only when they are short,
/// single-line identifier tokens. Never pass a payload, password, header,
/// URL, public/private key, signature, or raw error text as an identifier.
pub fn record_security_outcome(
    source: SecuritySource,
    outcome: SecurityOutcome,
    policy: SecurityPolicy,
    subject_id: Option<&str>,
    correlation_id: Option<&str>,
) {
    let source = source.as_str();
    let outcome_label = outcome.as_str();
    let error_kind = outcome.error_kind();
    let policy = policy.as_str();

    let mut labels = HashMap::new();
    labels.insert("source".to_string(), source.to_string());
    labels.insert("outcome".to_string(), outcome_label.to_string());
    labels.insert("error_kind".to_string(), error_kind.to_string());
    labels.insert("policy".to_string(), policy.to_string());
    increment_counter(SECURITY_OUTCOME_METRIC, 1, Some(labels));

    let subject_id = safe_security_identifier(subject_id);
    let correlation_id = safe_security_identifier(correlation_id);
    if outcome.is_warning() {
        warn!(
            event = SECURITY_OUTCOME_EVENT,
            source,
            outcome = outcome_label,
            error_kind,
            policy,
            subject_id,
            correlation_id,
            "Security-sensitive operation was not fully verified"
        );
    } else {
        info!(
            event = SECURITY_OUTCOME_EVENT,
            source,
            outcome = outcome_label,
            error_kind,
            policy,
            subject_id,
            correlation_id,
            "Security-sensitive operation verified"
        );
    }
}

pub(crate) fn safe_security_identifier(value: Option<&str>) -> &str {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return "";
    };
    if value.len() <= 160
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        value
    } else {
        "redacted"
    }
}

/// Record an agent operation with both metrics and structured logging
pub fn record_agent_operation(operation: &str, agent_id: &str, success: bool, duration_ms: u64) {
    // Create a tracing span for this operation
    let span = tracing::info_span!(
        "agent_operation",
        operation = operation,
        agent_id = agent_id,
        success = success,
        duration_ms = duration_ms
    );
    let _enter = span.enter();

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

    // Structured logging WITH ALL ORIGINAL METADATA
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
    // Create a tracing span for signature verification
    let span = tracing::debug_span!(
        "signature_verification",
        agent_id = agent_id,
        algorithm = algorithm,
        success = success
    );
    let _enter = span.enter();

    let mut tags = HashMap::new();
    tags.insert("algorithm".to_string(), algorithm.to_string());
    tags.insert("success".to_string(), success.to_string());

    // Metrics
    increment_counter("jacs_signature_verifications_total", 1, Some(tags));

    // Structured logging
    if success {
        debug!("Signature verification successful");
    } else {
        error!("Signature verification failed");
    }
}

/// Record network communication metrics
pub fn record_network_request(endpoint: &str, method: &str, status_code: u16, duration_ms: u64) {
    // Create a tracing span for network request
    let span = tracing::info_span!(
        "network_request",
        endpoint = endpoint,
        method = method,
        status_code = status_code,
        duration_ms = duration_ms
    );
    let _enter = span.enter();

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

    info!("Network request completed");
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
