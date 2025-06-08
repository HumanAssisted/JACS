use crate::config::{LogConfig, LogDestination};
use std::collections::HashMap;
use std::io;
use tracing::warn;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::non_blocking::WorkerGuard;
#[cfg(not(target_arch = "wasm32"))]
use tracing_appender::rolling::{RollingFileAppender, Rotation};

// #[cfg(not(target_arch = "wasm32"))] // OTLP types are not directly used in init_logs now
// use tracing_opentelemetry::OpenTelemetryLayer;
// #[cfg(not(target_arch = "wasm32"))]
// use opentelemetry_otlp::WithExportConfig;

#[cfg(not(target_arch = "wasm32"))]
pub fn init_logs(config: &LogConfig) -> Result<Option<WorkerGuard>, Box<dyn std::error::Error>> {
    if !config.enabled {
        return Ok(None);
    }

    let filter = EnvFilter::new(&config.level)
        .add_directive("hyper=off".parse()?)
        .add_directive("tonic=off".parse()?)
        .add_directive("h2=off".parse()?)
        .add_directive("reqwest=off".parse()?);

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
            Registry::default()
                .with(filter)
                .with(fmt::layer().with_writer(io::stderr))
                .try_init()?;
            Ok(None)
        }
        LogDestination::Otlp { endpoint, headers } => {
            if let Some(headers) = headers {
                warn!(
                    "OTLP headers configured: {:?}",
                    headers.keys().collect::<Vec<&String>>()
                );
            }
            warn!(
                "Warning: OTLP logging configured for {} but using Stderr fallback for now.",
                endpoint
            );
            Registry::default()
                .with(filter)
                .with(fmt::layer().with_writer(io::stderr))
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
