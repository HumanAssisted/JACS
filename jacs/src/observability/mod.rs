use opentelemetry::{KeyValue, global};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource, error::OTelSdkResult, logs::SdkLoggerProvider, metrics::SdkMeterProvider,
};
use prometheus::{Counter, Encoder, Gauge, Histogram, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, Once};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{Layer, filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
pub mod metrics;

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

// static INIT_ONCE: Once = Once::new();
// static METRICS_COLLECTOR: Mutex<Option<Arc<MetricsCollector>>> = Mutex::new(None);

// Add near the top with other statics
// static LOG_CONFIG: Mutex<Option<LogConfig>> = Mutex::new(None);

// Global state for providers
static PROVIDERS: Mutex<Option<ObservabilityProviders>> = Mutex::new(None);

// Store metrics config globally for file writing
static METRICS_CONFIG: Mutex<Option<MetricsConfig>> = Mutex::new(None);

// Add this back near the top with other statics
static METRICS_COLLECTOR: Mutex<Option<Arc<MetricsCollector>>> = Mutex::new(None);

struct ObservabilityProviders {
    logger_provider: Option<SdkLoggerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

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
    // OpenTelemetry metrics
    otel_meter: Option<opentelemetry::metrics::Meter>,
    // Prometheus metrics
    prometheus_registry: Option<Registry>,
    prometheus_counters: Arc<Mutex<HashMap<String, Counter>>>,
    prometheus_gauges: Arc<Mutex<HashMap<String, Gauge>>>,
    prometheus_histograms: Arc<Mutex<HashMap<String, Histogram>>>,
}

impl MetricsCollector {
    fn new(config: MetricsConfig) -> Self {
        let (otel_meter, prometheus_registry) = match &config.destination {
            MetricsDestination::Otlp { endpoint } => {
                // Initialize OpenTelemetry OTLP exporter
                let meter = global::meter("jacs");
                (Some(meter), None)
            }
            MetricsDestination::Prometheus { .. } => (None, Some(Registry::new())),
            _ => (None, None),
        };

        Self {
            config,
            otel_meter,
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
        match &self.config.destination {
            MetricsDestination::Otlp { .. } => {
                if let Some(meter) = &self.otel_meter {
                    let counter = meter
                        .u64_counter(name.to_string())
                        .with_description("Counter metric")
                        .with_unit("1")
                        .build();
                    // Convert tags to OpenTelemetry attributes
                    let attributes: Vec<opentelemetry::KeyValue> = tags
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(k, v)| opentelemetry::KeyValue::new(k, v))
                        .collect();
                    counter.add(value, &attributes);
                }
            }
            MetricsDestination::Prometheus { .. } => {
                // Use Prometheus registry
                if let Some(registry) = &self.prometheus_registry {
                    let mut counters = self.prometheus_counters.lock().unwrap();
                    let counter = counters.entry(name.to_string()).or_insert_with(|| {
                        let opts = prometheus::Opts::new(name, format!("Counter metric: {}", name));
                        let counter = Counter::with_opts(opts).unwrap();
                        registry.register(Box::new(counter.clone())).unwrap();
                        counter
                    });
                    counter.inc_by(value as f64);
                }
            }
            MetricsDestination::File { path } => {
                // Custom file format
                let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();
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
                let tags_str = tags.map(|t| format!(" {:?}", t)).unwrap_or_default();
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

fn get_resource() -> Resource {
    Resource::builder()
        .with_service_name("jacs")
        .with_attributes([KeyValue::new("service.version", env!("CARGO_PKG_VERSION"))])
        .build()
}

fn init_logs(config: &LogConfig) -> Result<Option<SdkLoggerProvider>, Box<dyn std::error::Error>> {
    if !config.enabled {
        return Ok(None);
    }

    let logger_provider = match &config.destination {
        LogDestination::Otlp { endpoint } => {
            let exporter = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build()?;

            SdkLoggerProvider::builder()
                .with_resource(get_resource())
                .with_batch_exporter(exporter)
                .build()
        }
        LogDestination::File { path } => {
            // For file output, we'll use a custom exporter that writes to file
            let exporter = FileLogExporter::new(path.clone());
            SdkLoggerProvider::builder()
                .with_resource(get_resource())
                .with_simple_exporter(exporter)
                .build()
        }
        LogDestination::Stderr | LogDestination::Null => {
            let exporter = opentelemetry_stdout::LogExporter::default();
            SdkLoggerProvider::builder()
                .with_resource(get_resource())
                .with_simple_exporter(exporter)
                .build()
        }
    };

    // Set up tracing subscriber with OpenTelemetry bridge
    let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);

    let level_filter = match config.level.as_str() {
        "debug" => "debug",
        "info" => "info",
        "warn" => "warn",
        "error" => "error",
        _ => "info",
    };

    let filter = EnvFilter::new(level_filter)
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());

    let otel_layer = otel_layer.with_filter(filter);

    // Only add stdout layer if not writing to file
    match &config.destination {
        LogDestination::File { .. } => {
            tracing_subscriber::registry()
                .with(otel_layer)
                .try_init()
                .ok(); // Ignore error if already initialized
        }
        _ => {
            let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

            tracing_subscriber::registry()
                .with(otel_layer)
                .with(fmt_layer)
                .try_init()
                .ok(); // Ignore error if already initialized
        }
    }

    Ok(Some(logger_provider))
}

fn init_metrics(
    config: &MetricsConfig,
) -> Result<Option<SdkMeterProvider>, Box<dyn std::error::Error>> {
    // Create and store the collector
    let collector = MetricsCollector::new(config.clone());
    if let Ok(mut stored_collector) = METRICS_COLLECTOR.lock() {
        *stored_collector = Some(Arc::new(collector));
    }

    // Store config for our custom file writing
    if let Ok(mut stored_config) = METRICS_CONFIG.lock() {
        *stored_config = Some(config.clone());
    }

    if !config.enabled {
        return Ok(None);
    }

    let meter_provider = match &config.destination {
        MetricsDestination::Otlp { endpoint } => {
            let exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build()?;

            SdkMeterProvider::builder()
                .with_periodic_exporter(exporter)
                .with_resource(get_resource())
                .build()
        }
        MetricsDestination::Prometheus { .. } => {
            // Use stdout exporter for now - Prometheus integration is complex
            let exporter = opentelemetry_stdout::MetricExporter::default();
            SdkMeterProvider::builder()
                .with_periodic_exporter(exporter)
                .with_resource(get_resource())
                .build()
        }
        MetricsDestination::File { path } => {
            // Create a custom file-writing metrics setup
            // We need to handle this in our public API functions instead
            let exporter = opentelemetry_stdout::MetricExporter::default();
            // Store the file path for our custom file writing
            // ...
            SdkMeterProvider::builder()
                .with_periodic_exporter(exporter)
                .with_resource(get_resource())
                .build()
        }
        MetricsDestination::Stdout => {
            let exporter = opentelemetry_stdout::MetricExporter::default();
            SdkMeterProvider::builder()
                .with_periodic_exporter(exporter)
                .with_resource(get_resource())
                .build()
        }
    };

    // Set as global provider
    global::set_meter_provider(meter_provider.clone());

    Ok(Some(meter_provider))
}

// Simplified file log exporter
#[derive(Debug)]
struct FileLogExporter {
    path: String,
}

impl FileLogExporter {
    fn new(path: String) -> Self {
        Self { path }
    }
}

impl opentelemetry_sdk::logs::LogExporter for FileLogExporter {
    async fn export(
        &self,
        batch: opentelemetry_sdk::logs::LogBatch<'_>,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        for (log_record, _instrumentation) in batch.iter() {
            let message = log_record
                .body()
                .map(|b| format!("{:?}", b))
                .unwrap_or_default();
            let log_line = format!(
                "{} {}\n",
                log_record.severity_text().unwrap_or("INFO"),
                message
            );

            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .and_then(|mut f| {
                    f.write_all(log_line.as_bytes())?;
                    f.flush()
                });
        }
        Ok(())
    }
}

pub fn init_observability(config: ObservabilityConfig) -> Result<(), Box<dyn std::error::Error>> {
    let logger_provider = init_logs(&config.logs)?;
    let meter_provider = init_metrics(&config.metrics)?;

    // Store providers for shutdown
    if let Ok(mut providers) = PROVIDERS.lock() {
        *providers = Some(ObservabilityProviders {
            logger_provider,
            meter_provider,
        });
    }

    Ok(())
}

pub fn reset_observability() {
    if let Ok(mut providers) = PROVIDERS.lock() {
        *providers = None;
    }
}

pub fn flush_observability() {
    // Simple approach - just wait a bit longer for async operations
    std::thread::sleep(std::time::Duration::from_millis(200));
}
