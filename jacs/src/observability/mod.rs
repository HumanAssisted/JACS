use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::warn;

pub mod convenience;
pub mod logs;
pub mod metrics;

#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::non_blocking::WorkerGuard;

static CONFIG: Mutex<Option<ObservabilityConfig>> = Mutex::new(None);

#[cfg(not(target_arch = "wasm32"))]
static LOG_WORKER_GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);

static TEST_METRICS_RECORDER_HANDLE: Mutex<Option<Arc<Mutex<Vec<metrics::CapturedMetric>>>>> =
    Mutex::new(None);

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

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogDestination {
    #[serde(rename = "http")]
    Http { endpoint: String },
    #[serde(rename = "console")]
    Console,
    #[serde(rename = "null")]
    Null,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

pub fn init_observability(
    config: ObservabilityConfig,
) -> Result<Option<Arc<Mutex<Vec<metrics::CapturedMetric>>>>, Box<dyn std::error::Error>> {
    if let Ok(mut stored_config) = CONFIG.lock() {
        *stored_config = Some(config.clone());
    } else {
        return Err("CONFIG lock poisoned".into());
    }

    // Attempt to initialize logs.
    // `tracing_subscriber::...try_init()` has its own `Once`.
    // Only the first *successful* call to `try_init` sets the global subscriber.
    match logs::init_logs(&config.logs) {
        Ok(guard_option) => {
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(new_guard) = guard_option {
                if let Ok(mut global_guard_handle) = LOG_WORKER_GUARD.lock() {
                    if let Some(old_guard) = global_guard_handle.take() {
                        drop(old_guard); // Ensure previous guard is flushed and dropped
                    }
                    *global_guard_handle = Some(new_guard);
                } else {
                    warn!(
                        "Warning: LOG_WORKER_GUARD lock poisoned during init, cannot store new guard."
                    );
                }
            }
        }
        Err(e) => {
            // This error often means a global subscriber was already set.
            // This is okay if the existing subscriber is compatible or if this config doesn't need to be the primary.
            warn!(
                "Info: logs::init_logs reported: {} (possibly already initialized or incompatible re-init)",
                e
            );
        }
    }

    // Attempt to initialize metrics.
    // `metrics::set_global_recorder` also has `Once` semantics.
    let mut metrics_handle_for_return: Option<Arc<Mutex<Vec<metrics::CapturedMetric>>>> = None;

    match metrics::init_metrics(&config.metrics) {
        Ok(captured_arc_option) => {
            if let Ok(mut global_metrics_handle) = TEST_METRICS_RECORDER_HANDLE.lock() {
                *global_metrics_handle = captured_arc_option.clone(); // Store Arc if File, or None otherwise
                metrics_handle_for_return = captured_arc_option;
            } else {
                warn!(
                    "Warning: TEST_METRICS_RECORDER_HANDLE lock poisoned, cannot store metrics Arc."
                );
            }
        }
        Err(e) => {
            // This error often means a global recorder was already set.
            warn!(
                "Info: metrics::init_metrics reported: {} (possibly already initialized or incompatible re-init)",
                e
            );

            // For File destination, still try to return existing handle if available
            if config.metrics.enabled
                && matches!(config.metrics.destination, MetricsDestination::File { .. })
            {
                if let Ok(handle) = TEST_METRICS_RECORDER_HANDLE.lock() {
                    metrics_handle_for_return = handle.clone();
                }
            }
        }
    }

    // Return handle for InMemoryMetricsRecorder if configured for File destination
    if config.metrics.enabled
        && matches!(config.metrics.destination, MetricsDestination::File { .. })
    {
        return Ok(metrics_handle_for_return);
    }

    Ok(None)
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
