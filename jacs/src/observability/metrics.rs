use crate::observability::{MetricsConfig, MetricsDestination};
use metrics::{
    CounterFn, GaugeFn, HistogramFn, counter, describe_counter, describe_gauge, describe_histogram,
    gauge, histogram,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[cfg(not(target_arch = "wasm32"))]
use metrics_exporter_prometheus::PrometheusBuilder;

#[cfg(not(target_arch = "wasm32"))]
use opentelemetry_otlp::WithExportConfig;

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

#[derive(Debug, Clone, Default)]
pub struct InMemoryMetricsRecorder {
    pub captured: Arc<Mutex<Vec<CapturedMetric>>>,
}

impl InMemoryMetricsRecorder {
    pub fn new() -> Self {
        Default::default()
    }
}

// Newtypes to implement the Fn traits
struct InMemoryCounter {
    name: String,
    labels: Vec<(String, String)>,
    captured: Arc<Mutex<Vec<CapturedMetric>>>,
}
impl CounterFn for InMemoryCounter {
    fn increment(&self, value: u64) {
        if let Ok(mut guard) = self.captured.lock() {
            guard.push(CapturedMetric::Counter {
                name: self.name.clone(),
                value,
                labels: self.labels.clone(),
            });
        }
    }

    fn absolute(&self, value: u64) {
        // For InMemory recorder, treat absolute as an increment for simplicity in testing.
        // Or, if you need to distinguish, add a new variant to CapturedMetric.
        if let Ok(mut guard) = self.captured.lock() {
            // For now, let's assume absolute also just "adds" to the captured events for testing.
            // A real counter might reset or set to this value.
            guard.push(CapturedMetric::Counter {
                name: self.name.clone(),
                value,
                labels: self.labels.clone(),
            });
        }
    }
}

struct InMemoryGauge {
    name: String,
    labels: Vec<(String, String)>,
    captured: Arc<Mutex<Vec<CapturedMetric>>>,
}
impl GaugeFn for InMemoryGauge {
    fn increment(&self, value: f64) { /* Optional: or panic, gauge usually uses set */
    }
    fn decrement(&self, value: f64) { /* Optional: or panic, gauge usually uses set */
    }
    fn set(&self, value: f64) {
        if let Ok(mut guard) = self.captured.lock() {
            guard.push(CapturedMetric::Gauge {
                name: self.name.clone(),
                value,
                labels: self.labels.clone(),
            });
        }
    }
}

struct InMemoryHistogram {
    name: String,
    labels: Vec<(String, String)>,
    captured: Arc<Mutex<Vec<CapturedMetric>>>,
}
impl HistogramFn for InMemoryHistogram {
    fn record(&self, value: f64) {
        if let Ok(mut guard) = self.captured.lock() {
            guard.push(CapturedMetric::Histogram {
                name: self.name.clone(),
                value,
                labels: self.labels.clone(),
            });
        }
    }
}

impl metrics::Recorder for InMemoryMetricsRecorder {
    fn describe_counter(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn register_counter(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        let name = key.name().to_string();
        let labels: Vec<(String, String)> = key
            .labels()
            .map(|lbl| (lbl.key().to_string(), lbl.value().to_string()))
            .collect();
        metrics::Counter::from_arc(Arc::new(InMemoryCounter {
            name,
            labels,
            captured: self.captured.clone(),
        }))
    }

    fn register_gauge(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        let name = key.name().to_string();
        let labels: Vec<(String, String)> = key
            .labels()
            .map(|lbl| (lbl.key().to_string(), lbl.value().to_string()))
            .collect();
        metrics::Gauge::from_arc(Arc::new(InMemoryGauge {
            name,
            labels,
            captured: self.captured.clone(),
        }))
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        let name = key.name().to_string();
        let labels: Vec<(String, String)> = key
            .labels()
            .map(|lbl| (lbl.key().to_string(), lbl.value().to_string()))
            .collect();
        metrics::Histogram::from_arc(Arc::new(InMemoryHistogram {
            name,
            labels,
            captured: self.captured.clone(),
        }))
    }
}

pub fn init_metrics(
    config: &MetricsConfig,
) -> Result<Option<Arc<Mutex<Vec<CapturedMetric>>>>, Box<dyn std::error::Error>> {
    if !config.enabled {
        return Ok(None);
    }

    let mut captured_metrics_arc_for_test: Option<Arc<Mutex<Vec<CapturedMetric>>>> = None;

    match &config.destination {
        #[cfg(not(target_arch = "wasm32"))]
        MetricsDestination::Prometheus { endpoint: _ } => {
            let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
            builder.install()?;
        }

        #[cfg(not(target_arch = "wasm32"))]
        MetricsDestination::Otlp { endpoint: _ } => {
            // OTLP metrics support requires complex setup - skip for now
        }

        MetricsDestination::File { path: _ } => {
            let recorder = InMemoryMetricsRecorder::new();
            captured_metrics_arc_for_test = Some(recorder.captured.clone());
            metrics::set_global_recorder(Box::new(recorder))?;
        }

        MetricsDestination::Stdout => {
            // No-op for now
        }
    }

    Ok(captured_metrics_arc_for_test)
}

// Public API functions using the metrics crate
pub fn increment_counter(name: &str, value: u64, tags: Option<HashMap<String, String>>) {
    match tags {
        Some(tags) => {
            let labels: Vec<(String, String)> = tags.into_iter().collect();
            counter!(name.to_string(), &labels).increment(value);
        }
        None => {
            counter!(name.to_string()).increment(value);
        }
    }
}

pub fn set_gauge(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    match tags {
        Some(tags) => {
            let labels: Vec<(String, String)> = tags.into_iter().collect();
            gauge!(name.to_string(), &labels).set(value);
        }
        None => {
            gauge!(name.to_string()).set(value);
        }
    }
}

pub fn record_histogram(name: &str, value: f64, tags: Option<HashMap<String, String>>) {
    match tags {
        Some(tags) => {
            let labels: Vec<(String, String)> = tags.into_iter().collect();
            histogram!(name.to_string(), &labels).record(value);
        }
        None => {
            histogram!(name.to_string()).record(value);
        }
    }
}
