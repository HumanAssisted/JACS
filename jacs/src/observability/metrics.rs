use crate::observability::{METRICS_COLLECTOR, METRICS_CONFIG, MetricsDestination};
use opentelemetry::{KeyValue, global};
use std::collections::HashMap;
use std::io::Write;
use tracing::{debug, error, info, warn};

// Public API for metrics using OpenTelemetry
pub fn increment_counter(name: &str, value: u64, tags: Option<HashMap<String, String>>) {
    if let Ok(collector) = METRICS_COLLECTOR.lock() {
        if let Some(collector) = collector.as_ref() {
            collector.increment_counter(name, value, tags);
        }
    }
}

pub fn set_gauge(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    // OpenTelemetry path
    let meter = global::meter("jacs");
    let gauge = meter.f64_gauge(name.to_string()).build();

    let attributes: Vec<KeyValue> = tags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| KeyValue::new(k, v))
        .collect();

    gauge.record(value, &attributes);

    // File writing path
    if let Ok(config) = METRICS_CONFIG.lock() {
        if let Some(config) = config.as_ref() {
            if let MetricsDestination::File { path } = &config.destination {
                let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();
                let line = format!("GAUGE: {} = {}{}\n", name, value, tags_str);
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| {
                        f.write_all(line.as_bytes())?;
                        f.flush()
                    });
            }
        }
    }
}

pub fn record_histogram(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    // OpenTelemetry path
    let meter = global::meter("jacs");
    let histogram = meter.f64_histogram(name.to_string()).build();

    let attributes: Vec<KeyValue> = tags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| KeyValue::new(k, v))
        .collect();

    histogram.record(value, &attributes);

    // File writing path
    if let Ok(config) = METRICS_CONFIG.lock() {
        if let Some(config) = config.as_ref() {
            if let MetricsDestination::File { path } = &config.destination {
                let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();
                let line = format!("HISTOGRAM: {} = {}{}\n", name, value, tags_str);
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| {
                        f.write_all(line.as_bytes())?;
                        f.flush()
                    });
            }
        }
    }
}

// Convenience functions using proper tracing
pub fn record_agent_operation(operation: &str, agent_id: &str, success: bool, duration_ms: u64) {
    let mut tags = HashMap::new();
    tags.insert("operation".to_string(), operation.to_string());
    tags.insert("agent_id".to_string(), agent_id.to_string());
    tags.insert("success".to_string(), success.to_string());

    increment_counter("jacs_agent_operations_total", 1, Some(tags.clone()));
    record_histogram(
        "jacs_agent_operation_duration_ms",
        duration_ms as f64,
        Some(tags),
    );

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

pub fn record_document_validation(doc_id: &str, schema_version: &str, valid: bool) {
    let mut tags = HashMap::new();
    tags.insert("schema_version".to_string(), schema_version.to_string());
    tags.insert("valid".to_string(), valid.to_string());

    increment_counter("jacs_document_validations_total", 1, Some(tags));

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

pub fn record_signature_verification(agent_id: &str, success: bool, algorithm: &str) {
    let mut tags = HashMap::new();
    tags.insert("algorithm".to_string(), algorithm.to_string());
    tags.insert("success".to_string(), success.to_string());

    increment_counter("jacs_signature_verifications_total", 1, Some(tags));

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
