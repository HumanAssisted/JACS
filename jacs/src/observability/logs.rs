use crate::config::{LogConfig, LogDestination};
use std::io;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize logging with a simple, sensible default configuration.
///
/// This function provides a quick way to set up logging that:
/// - Outputs to stderr
/// - Defaults to `info` level for JACS modules
/// - Uses the `RUST_LOG` environment variable for customization
/// - Suppresses verbose output from common networking crates
///
/// # Example
///
/// ```rust,ignore
/// use jacs::observability::logs::init_logging;
///
/// fn main() {
///     init_logging();  // Set up logging with defaults
///     // Your application code here
/// }
/// ```
///
/// # Environment Variables
///
/// - `RUST_LOG`: Standard Rust logging configuration. Defaults to `jacs=info` if not set.
///   Examples:
///   - `RUST_LOG=debug` - Enable debug logging for all modules
///   - `RUST_LOG=jacs=debug` - Enable debug logging for JACS only
///   - `RUST_LOG=jacs=trace,jacs::crypt=debug` - Fine-grained control
///
/// # Panics
///
/// This function will not panic even if a global subscriber is already set.
/// It will silently return in that case.
pub fn init_logging() {
    // Build filter from RUST_LOG env var, defaulting to jacs=info
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jacs=info"))
        .add_directive("hyper=warn".parse().expect("valid directive"))
        .add_directive("tonic=warn".parse().expect("valid directive"))
        .add_directive("h2=warn".parse().expect("valid directive"))
        .add_directive("reqwest=warn".parse().expect("valid directive"));

    // Try to initialize; if a subscriber already exists, this is a no-op
    let _ = Registry::default()
        .with(filter)
        .with(fmt::layer().with_writer(io::stderr))
        .try_init();
}

#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::non_blocking::WorkerGuard;
#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::rolling::{RollingFileAppender, Rotation};

#[cfg(all(not(target_arch = "wasm32"), feature = "otlp-logs"))]
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
#[cfg(all(not(target_arch = "wasm32"), feature = "otlp-logs"))]
use opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig, WithHttpConfig};
#[cfg(all(not(target_arch = "wasm32"), feature = "otlp-logs"))]
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider};

#[cfg(not(target_arch = "wasm32"))]
pub fn init_logs(config: &LogConfig) -> Result<Option<WorkerGuard>, Box<dyn std::error::Error>> {
    if !config.enabled {
        return Ok(None);
    }

    let filter = EnvFilter::new(&config.level)
        .add_directive("hyper=warn".parse()?)
        .add_directive("tonic=warn".parse()?)
        .add_directive("h2=warn".parse()?)
        .add_directive("reqwest=warn".parse()?);

    match &config.destination {
        LogDestination::File { path } => {
            let file_appender = RollingFileAppender::new(Rotation::DAILY, path, "app.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            Registry::default()
                .with(filter)
                .with(fmt::layer().with_writer(non_blocking).with_ansi(false))
                .try_init()?;
            Ok(Some(guard))
        }
        LogDestination::Stderr => {
            let _ = Registry::default()
                .with(filter)
                .with(fmt::layer().with_writer(io::stderr))
                .try_init();
            Ok(None)
        }
        LogDestination::Otlp {
            endpoint: _,
            headers: _,
        } => {
            #[cfg(all(not(target_arch = "wasm32"), feature = "otlp-logs"))]
            {
                // Create OTLP log exporter
                let exporter = LogExporter::builder()
                    .with_http()
                    .with_protocol(Protocol::HttpBinary)
                    .with_endpoint(endpoint)
                    .build()?;

                // Create logger provider
                let logger_provider = SdkLoggerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(Resource::builder().with_service_name("jacs-demo").build())
                    .build();

                // Create OpenTelemetry tracing bridge
                let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);

                Registry::default()
                    .with(filter)
                    .with(fmt::layer().with_writer(io::stderr)) // Also log to stderr for debugging
                    .with(otel_layer)
                    .try_init()?;
                return Ok(None);
            }
            #[cfg(any(target_arch = "wasm32", not(feature = "otlp-logs")))]
            {
                Err("OTLP logs feature not enabled: rebuild with --features otlp-logs".into())
            }
        }
        LogDestination::Null => Ok(None),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn init_logs(config: &LogConfig) -> Result<Option<()>, Box<dyn std::error::Error>> {
    if !config.enabled {
        return Ok(None);
    }

    let filter = EnvFilter::new(&config.level)
        .add_directive("hyper=off".parse()?)
        .add_directive("tonic=off".parse()?)
        .add_directive("h2=off".parse()?)
        .add_directive("reqwest=off".parse()?);

    if tracing::subscriber::try_with_default(|_| {}).is_err() {
        // No subscriber set yet, we can initialize
        Registry::default()
            .with(filter)
            .with(fmt::layer())
            .try_init()?;
    } else {
        // Subscriber already exists, just add our layer to it
        warn!("Subscriber already initialized, skipping logs initialization");
    }

    match &config.destination {
        LogDestination::Console => {
            Registry::default()
                .with(filter)
                .with(fmt::layer())
                .try_init()?;
        }
        LogDestination::Http { endpoint } => {
            warn!(
                "Warning: HTTP logging for WASM configured for {} but using Console fallback.",
                endpoint
            );
            Registry::default()
                .with(filter)
                .with(fmt::layer())
                .try_init()?;
        }
        LogDestination::Null => {
            // Do nothing - logging disabled
        }
    }
    Ok(None)
}
