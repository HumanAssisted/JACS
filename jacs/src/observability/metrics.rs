use crate::config::{MetricsConfig, MetricsDestination};
use opentelemetry::{KeyValue, global};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_otlp::WithExportConfig;

#[cfg(not(target_arch = "wasm32"))]
use opentelemetry::metrics::MeterProvider;

use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

// For testing - capture metrics calls
#[derive(Debug, Clone, PartialEq)]
pub enum CapturedMetric {
    Counter {
        name: String,
        value: u64,
        labels: Vec<(String, String)>,
    },
    Gauge {
        name: String,
        value: f64,
        labels: Vec<(String, String)>,
    },
    Histogram {
        name: String,
        value: f64,
        labels: Vec<(String, String)>,
    },
}

pub fn init_metrics(
    config: &MetricsConfig,
) -> Result<
    (
        Option<Arc<Mutex<Vec<CapturedMetric>>>>,
        Option<SdkMeterProvider>,
    ),
    Box<dyn std::error::Error>,
> {
    if !config.enabled {
        return Ok((None, None));
    }

    match &config.destination {
        #[cfg(not(target_arch = "wasm32"))]
        MetricsDestination::Otlp { endpoint, headers } => {
            use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
            use opentelemetry_sdk::{Resource, metrics::SdkMeterProvider};

            let exporter = MetricExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .with_protocol(Protocol::HttpBinary)
                .build()?;

            let reader = PeriodicReader::builder(exporter)
                .with_interval(Duration::from_secs(5))
                .build();

            let meter_provider = SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(Resource::builder().with_service_name("jacs-demo").build())
                .build();

            global::set_meter_provider(meter_provider.clone());
            tracing::info!("OTLP metrics export configured for {}", endpoint);

            Ok((None, Some(meter_provider)))
        }

        MetricsDestination::File { path: _ } => {
            // For file destination, return captured metrics for testing
            Ok((Some(Arc::new(Mutex::new(Vec::new()))), None))
        }

        MetricsDestination::Stdout => {
            // For stdout destination, return captured metrics for testing
            Ok((Some(Arc::new(Mutex::new(Vec::new()))), None))
        }

        #[cfg(not(target_arch = "wasm32"))]
        MetricsDestination::Prometheus { endpoint, headers } => {
            // For pure OTLP setup, we don't support direct Prometheus
            // You'd need to use the OTLP -> Collector -> Prometheus path
            Err("Direct Prometheus export not supported in OTLP-only mode. Use OTLP destination with collector.".into())
        }
    }
}

// Direct OpenTelemetry metrics functions
pub fn increment_counter(name: &str, value: u64, tags: Option<HashMap<String, String>>) {
    let meter = global::meter("jacs-demo");
    let counter = meter.u64_counter(name.to_string()).build();

    let attributes: Vec<KeyValue> = tags
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| KeyValue::new(k, v))
        .collect();

    counter.add(value, &attributes);

    tracing::debug!(
        "Incremented counter: {} = {}, tags: {:?}",
        name,
        value,
        attributes
    );
}

pub fn set_gauge(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    let meter = global::meter("jacs-demo");
    let gauge = meter.f64_gauge(name.to_string()).build();

    let attributes: Vec<KeyValue> = tags
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| KeyValue::new(k, v))
        .collect();

    gauge.record(value, &attributes);

    tracing::debug!("Set gauge: {} = {}, tags: {:?}", name, value, attributes);
}

pub fn record_histogram(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    let meter = global::meter("jacs-demo");
    let histogram = meter.f64_histogram(name.to_string()).build();

    let attributes: Vec<KeyValue> = tags
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| KeyValue::new(k, v))
        .collect();

    histogram.record(value, &attributes);

    tracing::debug!(
        "Recorded histogram: {} = {}, tags: {:?}",
        name,
        value,
        attributes
    );
}
