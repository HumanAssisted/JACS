# JACS Observability (simple, feature-gated)

JACS provides a minimal observability API. By default it sets up only local logs (stderr or file). Remote backends (OTLP logs/metrics/tracing) are optional and guarded by Cargo features.

## Quick Start

### 1. Initialize

Simplest setup uses file logs and no remote backends:

```rust
use jacs::init_default_observability;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_default_observability()?;
    Ok(())
}
```

This sets up:
- File-based logging at INFO level in `./logs/`
- No metrics or tracing by default

### 2. Custom configuration

For more control, use custom configuration:

```rust
use jacs::{init_custom_observability, ObservabilityConfig, LogConfig, MetricsConfig, 
           TracingConfig, SamplingConfig, LogDestination, MetricsDestination, TracingDestination};
use std::collections::HashMap;

let config = ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "debug".to_string(),
        destination: LogDestination::File { path: "./custom_logs".to_string() },
        headers: None,
    },
    metrics: MetricsConfig::default(),
    tracing: None,
};

init_custom_observability(config)?;
```

## Features and backends

- No extra features: stderr/file logs only.
- `observability-convenience`: enable convenience helpers (wrappers) for logs/metrics.
- `otlp-logs`: enable OTLP log export (pulls in OpenTelemetry + tokio).
- `otlp-metrics`: enable OTLP metrics export (pulls in OpenTelemetry + tokio).
- `otlp-tracing`: enable OTLP tracing export (pulls in OpenTelemetry + tokio).

If you request an unavailable backend at runtime, initialization returns an error with a clear message (e.g., "otlp-logs feature is not enabled").

Enable features when building:
```bash
cargo build --features otlp-logs,otlp-metrics,otlp-tracing
```

Tokio usage:
- Tokio is optional and pulled in only by OTLP features.
- Default build (no OTLP features) has no tokio dependency and is WASM-friendly.

Minimal OTLP examples:

Logs (requires `otlp-logs`):
```rust
let cfg = ObservabilityConfig {
  logs: LogConfig { enabled: true, level: "info".into(), destination: LogDestination::Otlp { endpoint: "http://collector:4318".into(), headers: None }, headers: None },
  ..Default::default()
};
init_custom_observability(cfg)?;
```

Metrics (requires `otlp-metrics`):
```rust
let cfg = ObservabilityConfig {
  metrics: MetricsConfig { enabled: true, destination: MetricsDestination::Otlp { endpoint: "http://collector:4318".into(), headers: None }, export_interval_seconds: Some(60), headers: None },
  ..Default::default()
};
init_custom_observability(cfg)?;
```

Tracing (requires `otlp-tracing`):
```rust
let cfg = ObservabilityConfig {
  tracing: Some(TracingConfig { enabled: true, sampling: SamplingConfig { ratio: 0.1, parent_based: true, rate_limit: Some(100) }, resource: None, destination: Some(TracingDestination::Otlp { endpoint: "http://collector:4318".into(), headers: None }) }),
  ..Default::default()
};
init_custom_observability(cfg)?;
```

Note: direct Prometheus export is not supported; route via an OTLP Collector.

### Compile recipes

- Default (local logs only):
```bash
cargo build
```

- Add convenience helpers only:
```bash
cargo build --features observability-convenience
```

- OTLP logs only:
```bash
cargo build --features otlp-logs
```

- OTLP metrics only:
```bash
cargo build --features otlp-metrics
```

- OTLP tracing only:
```bash
cargo build --features otlp-tracing
```

- Full stack (helpers + logs + metrics + tracing):
```bash
cargo build --features "observability-convenience otlp-logs otlp-metrics otlp-tracing"
```

WASM builds:
- Build without OTLP features to avoid async runtime dependencies.
- Use stderr/file logging destinations only.

## Configuration Reference

### ObservabilityConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `logs` | `LogConfig` | Logging configuration | See LogConfig defaults |
| `metrics` | `MetricsConfig` | Metrics configuration | Disabled by default |
| `tracing` | `Option<TracingConfig>` | Distributed tracing configuration | `None` (disabled) |

### LogConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `enabled` | `bool` | Enable/disable logging | `true` |
| `level` | `String` | Log level: "trace", "debug", "info", "warn", "error" | `"info"` |
| `destination` | `LogDestination` | Where to send logs | `LogDestination::Stderr` |
| `headers` | `Option<HashMap<String, String>>` | Additional headers for HTTP destinations | `None` |

### MetricsConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `enabled` | `bool` | Enable/disable metrics | `false` |
| `destination` | `MetricsDestination` | Where to send metrics | `MetricsDestination::Stdout` |
| `export_interval_seconds` | `Option<u64>` | How often to export metrics | `None` |
| `headers` | `Option<HashMap<String, String>>` | Additional headers for HTTP destinations | `None` |

### TracingConfig (requires `otlp-tracing` for remote export)

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `enabled` | `bool` | Enable/disable distributed tracing | Required |
| `sampling` | `SamplingConfig` | Sampling configuration | See SamplingConfig |
| `resource` | `Option<ResourceConfig>` | Service resource information | `None` |
| `destination` | `Option<TracingDestination>` | Where to send traces | `None` |

### SamplingConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `ratio` | `f64` | Sampling ratio (0.0 to 1.0) | `1.0` (100%) |
| `parent_based` | `bool` | Use parent span sampling decision | `true` |
| `rate_limit` | `Option<u32>` | Maximum samples per second | `None` |

### ResourceConfig (optional)

| Field | Type | Description |
|-------|------|-------------|
| `service_name` | `String` | Name of the service |
| `service_version` | `Option<String>` | Version of the service |
| `environment` | `Option<String>` | Environment (dev, prod, etc.) |
| `attributes` | `HashMap<String, String>` | Additional resource attributes |

## Destinations

### Log Destinations

```rust
// Standard error output
LogDestination::Stderr

// File-based logging with daily rotation
LogDestination::File { 
    path: "./logs".to_string() 
}

// OpenTelemetry Protocol (OTLP) with optional headers (requires feature `otlp-logs`)
LogDestination::Otlp { 
    endpoint: "http://collector:4318".to_string(),
    headers: Some({
        let mut h = HashMap::new();
        h.insert("Authorization".to_string(), "Bearer token123".to_string());
        h
    }),
}

// Disable logging
LogDestination::Null
```

### Metrics Destinations

```rust
// Standard output
MetricsDestination::Stdout

// File export
MetricsDestination::File { 
    path: "./metrics.txt".to_string() 
}

// OpenTelemetry Protocol (OTLP) (requires feature `otlp-metrics`)
MetricsDestination::Otlp { 
    endpoint: "http://collector:4318".to_string(),
    headers: None,
}
```

## Logging

### Standard Tracing Macros

Use standard `tracing` macros for general application logging:

```rust
use tracing::{info, debug, warn, error, trace};

trace!("Detailed debugging information");
debug!("Processing document: {}", document_id);
info!("Agent operation completed successfully");
warn!("Configuration value missing, using default");
error!("Failed to validate signature: {}", error);
```

### Domain-Specific Convenience Functions

JACS provides convenience functions for common operations:

```rust
use jacs::observability::convenience::{
    record_agent_operation,
    record_document_validation, 
    record_signature_verification,
};

// Record agent operations (load, save, sign, etc.)
record_agent_operation("load_agent", "agent_123", true, 150);

// Record document validation events
record_document_validation("doc_456", "v1.0", false);

// Record signature verification events
record_signature_verification("agent_123", true, "Ed25519");
```

## Metrics

The system can record metrics via OTLP when enabled.

### Manual Metrics

You can also record custom metrics:

```rust
use jacs::observability::metrics::{increment_counter, set_gauge, record_histogram};
use std::collections::HashMap;

let mut tags = HashMap::new();
tags.insert("service".to_string(), "my_service".to_string());

increment_counter("requests_total", 1, Some(tags.clone()));
set_gauge("memory_usage_bytes", 1024.0, Some(tags.clone()));
record_histogram("response_time_ms", 123.4, Some(tags));
```

## Distributed Tracing (requires `otlp-tracing`)

Enable distributed tracing to track requests across service boundaries by setting `TracingConfig` with an OTLP destination.

## Authentication & Headers

For secure endpoints, use headers for authentication where supported.

## Example Configurations

### Development
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "debug".to_string(),
        destination: LogDestination::Stderr,
        headers: None,
    },
    metrics: MetricsConfig::default(),
    tracing: None, // Disabled for development
}
```

### Production with OTLP Collector (features enabled)
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "info".to_string(),
        destination: LogDestination::Otlp { endpoint: "http://collector:4318".to_string(), headers: None },
        headers: None,
    },
    metrics: MetricsConfig { enabled: true, destination: MetricsDestination::Otlp { endpoint: "http://collector:4318".into(), headers: None }, export_interval_seconds: Some(60), headers: None },
    tracing: Some(TracingConfig { enabled: true, sampling: SamplingConfig { ratio: 0.01, parent_based: true, rate_limit: Some(1000) }, resource: None, destination: Some(TracingDestination::Otlp { endpoint: "http://collector:4318".into(), headers: None }) }),
}
```

### Testing
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "trace".to_string(),
        destination: LogDestination::File { path: "./test_logs".to_string() },
        headers: None,
    },
    metrics: MetricsConfig { enabled: false, destination: MetricsDestination::Stdout, export_interval_seconds: None, headers: None },
    tracing: None,
}
```

## Integration with `jacs.config.json`

Add observability to your `jacs.config.json`:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info",
      "destination": { "file": { "path": "./logs" } }
    },
    "metrics": { "enabled": false },
    "tracing": null
  }
}
```

## Best Practices

1. **Initialize Early**: Call the initialization function as early as possible in your application
2. **Use Appropriate Log Levels**: choose levels suitable for your environment
3. **Include Context**: Add relevant context to your logs (agent IDs, operation types, etc.)
4. **Keep It Minimal**: Enable features only when you need remote export

## Troubleshooting

- **Global Subscriber Already Set**: This can occur if multiple initializations run; usually safe to ignore.
- **Feature Not Enabled**: If you see an error like "otlp-logs feature is not enabled", rebuild with the required feature.

## Run the Example

```bash
cargo run --example observability_demo
```

This will create log files in `./logs/`. Enable OTLP features and configure endpoints to export remotely. 