use crate::config::{LogConfig, LogDestination};
use std::io;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::non_blocking::WorkerGuard;
#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::rolling::{RollingFileAppender, Rotation};

#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig, WithHttpConfig};
#[cfg(not(target_arch = "wasm32"))]
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
            endpoint,
            headers: _,
        } => {
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
            Ok(None)
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
