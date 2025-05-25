use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::{Mutex, Once};

pub mod convenience;
pub mod logs;
pub mod metrics;

#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::non_blocking::WorkerGuard;

static INIT: Once = Once::new();
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
    INIT.call_once(|| {
        // This block runs only once. Store the first config that triggered initialization.
        if let Ok(mut stored_config) = CONFIG.lock() {
            *stored_config = Some(config.clone());
        }

        // Initialize logs using the config from the *first* call.
        match logs::init_logs(&config.logs) {
            Ok(guard_option) =>
            {
                #[cfg(not(target_arch = "wasm32"))]
                if let Some(guard) = guard_option {
                    if let Ok(mut global_guard_handle) = LOG_WORKER_GUARD.lock() {
                        *global_guard_handle = Some(guard);
                    } else {
                        eprintln!("Error: LOG_WORKER_GUARD lock poisoned during init.");
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to initialize logging: {}", e);
            }
        }

        // Initialize metrics using the config from the *first* call.
        match metrics::init_metrics(&config.metrics) {
            Ok(captured_arc_option) => {
                // If metrics init returns an Arc (i.e., for File destination), store it globally.
                if captured_arc_option.is_some() {
                    if let Ok(mut global_metrics_handle) = TEST_METRICS_RECORDER_HANDLE.lock() {
                        *global_metrics_handle = captured_arc_option;
                    } else {
                        eprintln!("Error: TEST_METRICS_RECORDER_HANDLE lock poisoned during init.");
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to initialize metrics: {}", e);
            }
        }
    });

    // After `call_once` (i.e., for every call to `init_observability`):
    // If the *current* call's config asks for File metrics, return the stored handle.
    if config.metrics.enabled
        && matches!(config.metrics.destination, MetricsDestination::File { .. })
    {
        if let Ok(handle) = TEST_METRICS_RECORDER_HANDLE.lock() {
            return Ok(handle.clone());
        } else {
            eprintln!(
                "Error: TEST_METRICS_RECORDER_HANDLE lock poisoned when trying to return handle."
            );
            // Fallthrough to Ok(None) or return specific error. For tests, Ok(None) will cause .expect() to fail.
        }
    }

    Ok(None) // Default: not File metrics, or handle somehow not available.
}

pub fn get_config() -> Option<ObservabilityConfig> {
    CONFIG.lock().ok()?.clone()
}

pub fn reset_observability() {
    // Clear the stored global configuration.
    if let Ok(mut config_handle) = CONFIG.lock() {
        *config_handle = None;
    } else {
        eprintln!("Error: CONFIG lock poisoned during reset.");
    }

    // For the metrics test handle, if it exists, clear the *contents* (the Vec).
    // The Arc itself remains in TEST_METRICS_RECORDER_HANDLE for subsequent tests.
    if let Ok(handle_option) = TEST_METRICS_RECORDER_HANDLE.lock() {
        if let Some(arc) = handle_option.as_ref() {
            // Borrow to check Some
            if let Ok(mut captured_metrics_vec) = arc.lock() {
                captured_metrics_vec.clear();
            } else {
                eprintln!(
                    "Error: TEST_METRICS_RECORDER_HANDLE's inner Arc<Mutex<Vec>> lock poisoned during reset."
                );
            }
        }
    } else {
        eprintln!("Error: TEST_METRICS_RECORDER_HANDLE outer lock poisoned during reset check.");
    }

    // For file logging, take and drop the worker guard.
    // This ensures logs from the previous test are flushed and the worker is shut down.
    // The `INIT: Once` ensures `logs::init_logs` isn't called again to create a new guard
    // unless it's a new program run. For serial tests, this guard is setup once.
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(mut guard_opt_handle) = LOG_WORKER_GUARD.lock() {
            if let Some(guard) = guard_opt_handle.take() {
                drop(guard); // Explicitly drop to shut down worker and flush.
            }
        } else {
            eprintln!("Error: LOG_WORKER_GUARD lock poisoned during reset.");
        }
    }
}

pub fn flush_observability() {
    // The main flushing for file logs is handled by dropping the LOG_WORKER_GUARD in `reset_observability`.
    // This function can remain as a small safety delay for any other truly async operations
    // not managed by explicit guards or flush mechanisms.
    std::thread::sleep(std::time::Duration::from_millis(50));
}
