use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::sync::{Arc, Mutex};
use tracing::warn;

pub mod convenience;
pub mod logs;
pub mod metrics;

// Re-export config types so existing imports still work
pub use crate::config::{
    LogConfig, LogDestination, MetricsConfig, MetricsDestination, ObservabilityConfig,
    ResourceConfig, SamplingConfig, TracingConfig, TracingDestination,
};

#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::non_blocking::WorkerGuard;

static CONFIG: Mutex<Option<ObservabilityConfig>> = Mutex::new(None);

#[cfg(not(target_arch = "wasm32"))]
static LOG_WORKER_GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);

static TEST_METRICS_RECORDER_HANDLE: Mutex<Option<Arc<Mutex<Vec<metrics::CapturedMetric>>>>> =
    Mutex::new(None);

pub fn init_observability(
    config: ObservabilityConfig,
) -> Result<Option<Arc<Mutex<Vec<metrics::CapturedMetric>>>>, Box<dyn std::error::Error>> {
    if let Ok(mut stored_config) = CONFIG.lock() {
        *stored_config = Some(config.clone());
    } else {
        return Err("CONFIG lock poisoned".into());
    }

    // Initialize tracing FIRST (before logs!)
    if let Some(tracing_config) = &config.tracing {
        if tracing_config.enabled {
            match init_tracing(tracing_config) {
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        "Info: init_tracing reported: {} (possibly already initialized)",
                        e
                    );
                }
            }
        }
    }

    // Initialize logs SECOND - but modify logs.rs to NOT call try_init if subscriber exists
    match logs::init_logs(&config.logs) {
        Ok(guard_option) =>
        {
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(new_guard) = guard_option {
                if let Ok(mut global_guard_handle) = LOG_WORKER_GUARD.lock() {
                    if let Some(old_guard) = global_guard_handle.take() {
                        drop(old_guard);
                    }
                    *global_guard_handle = Some(new_guard);
                }
            }
        }
        Err(e) => {
            warn!(
                "Info: logs::init_logs reported: {} (possibly already initialized)",
                e
            );
        }
    }

    // Initialize metrics last
    let mut metrics_handle_for_return: Option<Arc<Mutex<Vec<metrics::CapturedMetric>>>> = None;

    match metrics::init_metrics(&config.metrics) {
        Ok((captured_arc_option, _meter_provider)) => {
            if let Ok(mut global_metrics_handle) = TEST_METRICS_RECORDER_HANDLE.lock() {
                *global_metrics_handle = captured_arc_option.clone();
                metrics_handle_for_return = captured_arc_option;
            }
        }
        Err(e) => {
            warn!(
                "Info: metrics::init_metrics reported: {} (possibly already initialized)",
                e
            );
        }
    }

    Ok(metrics_handle_for_return)
}

pub fn get_config() -> Option<ObservabilityConfig> {
    CONFIG.lock().ok()?.clone()
}

pub fn reset_observability() {
    if let Ok(mut config_handle) = CONFIG.lock() {
        *config_handle = None;
    }

    if let Ok(handle_option) = TEST_METRICS_RECORDER_HANDLE.lock() {
        if let Some(arc) = handle_option.as_ref() {
            if let Ok(mut captured_metrics_vec) = arc.lock() {
                captured_metrics_vec.clear();
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(mut guard_opt_handle) = LOG_WORKER_GUARD.lock() {
            if let Some(guard) = guard_opt_handle.take() {
                drop(guard); // Explicitly drop to shut down worker and flush.
            }
        }
    }
}

/// Force reset for tests - clears global state more aggressively
pub fn force_reset_for_tests() {
    reset_observability();

    // Clear the global metrics recorder handle
    if let Ok(mut handle) = TEST_METRICS_RECORDER_HANDLE.lock() {
        *handle = None;
    }

    // Give time for async operations to complete
    std::thread::sleep(std::time::Duration::from_millis(100));
}

pub fn flush_observability() {
    // Primarily, flushing is handled by dropping LOG_WORKER_GUARD in reset_observability.
    // A small explicit sleep can help ensure file system operations complete in CI.
    std::thread::sleep(std::time::Duration::from_millis(50));
}

#[cfg(not(target_arch = "wasm32"))]
fn init_tracing(config: &TracingConfig) -> Result<(), Box<dyn std::error::Error>> {
    use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
    use opentelemetry_sdk::{
        Resource,
        trace::{Sampler, SdkTracerProvider},
    };
    use tracing_subscriber::{Registry, layer::SubscriberExt};

    // Get endpoint and ensure it has the correct path for HTTP OTLP
    let endpoint = config
        .destination
        .as_ref()
        .map(|dest| match dest {
            crate::config::TracingDestination::Otlp { endpoint, .. } => {
                // Ensure endpoint has /v1/traces path for HTTP OTLP
                if endpoint.ends_with("/v1/traces") {
                    endpoint.clone()
                } else if endpoint.ends_with("/") {
                    format!("{}v1/traces", endpoint)
                } else {
                    format!("{}/v1/traces", endpoint)
                }
            }
            crate::config::TracingDestination::Jaeger { endpoint, .. } => endpoint.clone(),
        })
        .unwrap_or_else(|| "http://localhost:4318/v1/traces".to_string());

    println!("DEBUG: Using OTLP endpoint: {}", endpoint);

    // Use blocking HTTP client (enabled by "reqwest-blocking-client" feature)
    let exporter = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .build()?;

    println!("DEBUG: SpanExporter built successfully with blocking client");

    // Build provider (your existing code)
    let service_name = config
        .resource
        .as_ref()
        .map(|r| r.service_name.clone())
        .unwrap_or_else(|| "jacs-demo".to_string());

    let mut resource_builder = Resource::builder().with_service_name(service_name.clone());

    if let Some(resource_config) = &config.resource {
        if let Some(version) = &resource_config.service_version {
            resource_builder =
                resource_builder.with_attribute(KeyValue::new("service.version", version.clone()));
        }
        if let Some(env) = &resource_config.environment {
            resource_builder =
                resource_builder.with_attribute(KeyValue::new("environment", env.clone()));
        }
        for (k, v) in &resource_config.attributes {
            resource_builder = resource_builder.with_attribute(KeyValue::new(k.clone(), v.clone()));
        }
    }

    let resource = resource_builder.build();

    let sampler = if config.sampling.ratio < 1.0 {
        Sampler::TraceIdRatioBased(config.sampling.ratio)
    } else {
        Sampler::AlwaysOn
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    let tracer = provider.tracer(service_name);
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let subscriber = Registry::default()
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer());

    tracing::subscriber::set_global_default(subscriber)?;
    global::set_tracer_provider(provider);

    println!("DEBUG: OpenTelemetry tracing initialized with blocking HTTP client");
    Ok(())
}
