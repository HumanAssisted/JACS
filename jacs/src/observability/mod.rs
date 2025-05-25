use opentelemetry::global;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use prometheus::{Counter, Encoder, Gauge, Histogram, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// "observability": {
//     "logs": {
//       "enabled": true,
//       "level": "info",
//       "destination": {
//         "type": "file",
//         "path": "/var/log/jacs.log"
//       }
//     },
//     "metrics": {
//       "enabled": true,
//       "destination": {
//         "type": "prometheus",
//         "endpoint": "http://localhost:9090"
//       },
//       "export_interval_seconds": 30
//     }
//   }
// }

// Simple global state
static METRICS_COLLECTOR: Mutex<Option<Arc<MetricsCollector>>> = Mutex::new(None);

// Add near the top with other statics
static LOG_CONFIG: Mutex<Option<LogConfig>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    pub logs: LogConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub enabled: bool,
    pub level: String,
    pub destination: LogDestination,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub destination: MetricsDestination,
    pub export_interval_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LogDestination {
    #[serde(rename = "stderr")]
    Stderr,
    #[serde(rename = "file")]
    File { path: String },
    #[serde(rename = "otlp")]
    Otlp { endpoint: String },
    #[serde(rename = "null")]
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MetricsDestination {
    #[serde(rename = "otlp")]
    Otlp { endpoint: String },
    #[serde(rename = "prometheus")]
    Prometheus { endpoint: String },
    #[serde(rename = "file")]
    File { path: String },
    #[serde(rename = "stdout")]
    Stdout,
}

pub struct MetricsCollector {
    config: MetricsConfig,
    prometheus_registry: Option<Registry>,
    prometheus_counters: Arc<Mutex<HashMap<String, Counter>>>,
    prometheus_gauges: Arc<Mutex<HashMap<String, Gauge>>>,
    prometheus_histograms: Arc<Mutex<HashMap<String, Histogram>>>,
}

impl MetricsCollector {
    fn new(config: MetricsConfig) -> Self {
        let prometheus_registry = match &config.destination {
            MetricsDestination::Prometheus { .. } => Some(Registry::new()),
            _ => None,
        };

        Self {
            config,
            prometheus_registry,
            prometheus_counters: Arc::new(Mutex::new(HashMap::new())),
            prometheus_gauges: Arc::new(Mutex::new(HashMap::new())),
            prometheus_histograms: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn increment_counter(&self, name: &str, value: u64, tags: Option<HashMap<String, String>>) {
        if !self.config.enabled {
            return;
        }
        self.export_counter(name, value, tags);
    }

    pub fn set_gauge(&self, name: &str, value: f64, tags: Option<HashMap<String, String>>) {
        if !self.config.enabled {
            return;
        }
        self.export_gauge(name, value, tags);
    }

    pub fn record_histogram(&self, name: &str, value: f64, tags: Option<HashMap<String, String>>) {
        if !self.config.enabled {
            return;
        }
        self.export_histogram(name, value, tags);
    }

    fn export_counter(&self, name: &str, value: u64, tags: Option<HashMap<String, String>>) {
        let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();

        match &self.config.destination {
            MetricsDestination::File { path } => {
                let line = format!("COUNTER: {} += {}{}\n", name, value, tags_str);
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| {
                        f.write_all(line.as_bytes())?;
                        f.flush()
                    });
            }
            MetricsDestination::Stdout => {
                println!("COUNTER: {} += {}{}", name, value, tags_str);
            }
            _ => {
                println!("COUNTER: {} += {}{}", name, value, tags_str);
            }
        }
    }

    fn export_gauge(&self, name: &str, value: f64, tags: Option<HashMap<String, String>>) {
        let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();

        match &self.config.destination {
            MetricsDestination::File { path } => {
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
            MetricsDestination::Stdout => {
                println!("GAUGE: {} = {}{}", name, value, tags_str);
            }
            _ => {
                println!("GAUGE: {} = {}{}", name, value, tags_str);
            }
        }
    }

    fn export_histogram(&self, name: &str, value: f64, tags: Option<HashMap<String, String>>) {
        let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();

        match &self.config.destination {
            MetricsDestination::File { path } => {
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
            MetricsDestination::Stdout => {
                println!("HISTOGRAM: {} = {}{}", name, value, tags_str);
            }
            _ => {
                println!("HISTOGRAM: {} = {}{}", name, value, tags_str);
            }
        }
    }
}

pub fn init_observability(config: ObservabilityConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Store log config for later use
    if config.logs.enabled {
        if let Ok(mut guard) = LOG_CONFIG.lock() {
            *guard = Some(config.logs.clone());
        }
        println!(
            "Logging enabled: level={}, destination={:?}",
            config.logs.level, config.logs.destination
        );
    }

    // Initialize metrics
    if config.metrics.enabled {
        let collector = Arc::new(MetricsCollector::new(config.metrics.clone()));
        if let Ok(mut guard) = METRICS_COLLECTOR.lock() {
            *guard = Some(collector);
        }
    }

    Ok(())
}

// Public API
pub fn increment_counter(name: &str, value: u64, tags: Option<HashMap<String, String>>) {
    if let Ok(guard) = METRICS_COLLECTOR.lock() {
        if let Some(collector) = guard.as_ref() {
            collector.increment_counter(name, value, tags);
        }
    }
}

pub fn set_gauge(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    if let Ok(guard) = METRICS_COLLECTOR.lock() {
        if let Some(collector) = guard.as_ref() {
            collector.set_gauge(name, value, tags);
        }
    }
}

pub fn record_histogram(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    if let Ok(guard) = METRICS_COLLECTOR.lock() {
        if let Some(collector) = guard.as_ref() {
            collector.record_histogram(name, value, tags);
        }
    }
}

// Convenience functions
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

    let log_msg = format!(
        "Agent operation: {} {} {} {}ms",
        operation,
        agent_id,
        if success { "SUCCESS" } else { "FAILED" },
        duration_ms
    );
    if success {
        write_log("INFO", &log_msg);
    } else {
        write_log("ERROR", &log_msg);
    }
}

pub fn record_document_validation(doc_id: &str, schema_version: &str, valid: bool) {
    let mut tags = HashMap::new();
    tags.insert("schema_version".to_string(), schema_version.to_string());
    tags.insert("valid".to_string(), valid.to_string());

    increment_counter("jacs_document_validations_total", 1, Some(tags));
    println!(
        "Document validation: {} {} {}",
        doc_id,
        schema_version,
        if valid { "VALID" } else { "INVALID" }
    );
}

pub fn record_signature_verification(agent_id: &str, success: bool, algorithm: &str) {
    let mut tags = HashMap::new();
    tags.insert("algorithm".to_string(), algorithm.to_string());
    tags.insert("success".to_string(), success.to_string());

    increment_counter("jacs_signature_verifications_total", 1, Some(tags));

    let log_msg = format!(
        "Signature verification: {} {} {}",
        agent_id,
        algorithm,
        if success { "SUCCESS" } else { "FAILED" }
    );
    if success {
        write_log("DEBUG", &log_msg);
    } else {
        write_log("ERROR", &log_msg);
    }
}

pub fn reset_observability() {
    if let Ok(mut guard) = METRICS_COLLECTOR.lock() {
        *guard = None;
    }
}

pub fn flush_observability() {
    std::thread::sleep(std::time::Duration::from_millis(10));
}

// Add a simple log function
fn write_log(level: &str, message: &str) {
    if let Ok(guard) = LOG_CONFIG.lock() {
        if let Some(config) = guard.as_ref() {
            match &config.destination {
                LogDestination::File { path } => {
                    let log_line = format!("{} {}\n", level, message);
                    let _ = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .and_then(|mut f| {
                            f.write_all(log_line.as_bytes())?;
                            f.flush()
                        });
                }
                _ => {
                    println!("{} {}", level, message);
                }
            }
        }
    }
}

// Add these public functions for the tests
pub fn info(message: &str) {
    write_log("INFO", message);
}

pub fn warn(message: &str) {
    write_log("WARN", message);
}
