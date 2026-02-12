# Observability (Rust API)

This page covers the Rust-specific observability API: `ObservabilityConfig`, `LogDestination`, `MetricsConfig`, `TracingConfig`, and related types. For a cross-language guide covering structured events, OTEL collector setup, and monitoring backend integration, see the [Observability & Monitoring Guide](../guides/observability.md).

JACS provides comprehensive observability features including logging, metrics, and distributed tracing. This chapter covers configuring and using these features in your Rust applications.

## Overview

JACS observability is built on the OpenTelemetry standard, providing:

- **Logging**: Structured logging with multiple destinations
- **Metrics**: Counters, gauges, and histograms for monitoring
- **Tracing**: Distributed tracing for request flows

## Feature Flags

Enable observability features in your `Cargo.toml`:

```toml
[dependencies]
jacs = { version = "0.3", features = ["observability"] }
```

| Feature | Description |
|---------|-------------|
| `observability` | Core observability support |
| `observability-convenience` | Helper functions for recording operations |
| `otlp-logs` | OTLP log export support |
| `otlp-metrics` | OTLP metrics export support |
| `otlp-tracing` | OTLP distributed tracing support |

## Quick Start

### Default Configuration

The simplest way to enable observability:

```rust
use jacs::init_default_observability;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_default_observability()?;

    // Your application code...

    Ok(())
}
```

This sets up:
- File-based logging to `./logs/` with daily rotation
- Metrics disabled by default
- Tracing disabled by default

### Custom Configuration

For more control, use `init_custom_observability`:

```rust
use jacs::{
    init_custom_observability,
    ObservabilityConfig,
    LogConfig,
    LogDestination,
    MetricsConfig,
    MetricsDestination,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ObservabilityConfig {
        logs: LogConfig {
            enabled: true,
            level: "info".to_string(),
            destination: LogDestination::Stderr,
            headers: None,
        },
        metrics: MetricsConfig {
            enabled: false,
            destination: MetricsDestination::Stdout,
            export_interval_seconds: None,
            headers: None,
        },
        tracing: None,
    };

    init_custom_observability(config)?;
    Ok(())
}
```

## Logging

### Log Levels

Supported log levels (from most to least verbose):
- `trace`
- `debug`
- `info`
- `warn`
- `error`

### Log Destinations

#### Stderr (Default)

```rust
LogDestination::Stderr
```

Logs to standard error. Useful for development and containerized environments.

#### File

```rust
LogDestination::File {
    path: "./logs".to_string(),
}
```

Logs to rotating files with daily rotation. Creates files like `app.log.2024-01-15`.

#### OTLP

```rust
LogDestination::Otlp {
    endpoint: "http://localhost:4318".to_string(),
    headers: None,
}
```

Exports logs via OpenTelemetry Protocol. Requires `otlp-logs` feature.

#### Null

```rust
LogDestination::Null
```

Disables logging completely.

### Using Logs

JACS uses the `tracing` crate for logging:

```rust
use tracing::{info, debug, warn, error};

fn process_document() {
    info!("Processing document");
    debug!("Document details: {:?}", doc);

    if let Err(e) = verify() {
        error!("Verification failed: {}", e);
    }
}
```

## Metrics

### Enabling Metrics

```rust
MetricsConfig {
    enabled: true,
    destination: MetricsDestination::Otlp {
        endpoint: "http://localhost:4318".to_string(),
        headers: None,
    },
    export_interval_seconds: Some(30),
    headers: None,
}
```

### Metrics Destinations

#### OTLP

```rust
MetricsDestination::Otlp {
    endpoint: "http://localhost:4318".to_string(),
    headers: None,
}
```

Exports to an OpenTelemetry collector. Requires `otlp-metrics` feature.

#### Prometheus (via Collector)

```rust
MetricsDestination::Prometheus {
    endpoint: "http://localhost:9090".to_string(),
    headers: None,
}
```

Note: Direct Prometheus export requires routing through an OTLP collector.

#### File

```rust
MetricsDestination::File {
    path: "./metrics.txt".to_string(),
}
```

Writes metrics to a file.

#### Stdout

```rust
MetricsDestination::Stdout
```

Prints metrics to standard output. Useful for testing.

### Recording Metrics

JACS provides convenience functions for common metrics:

```rust
use jacs::observability::metrics::{increment_counter, set_gauge, record_histogram};
use std::collections::HashMap;

// Increment a counter
let mut tags = HashMap::new();
tags.insert("operation".to_string(), "sign".to_string());
increment_counter("jacs_operations_total", 1, Some(tags));

// Set a gauge value
set_gauge("jacs_documents_active", 42.0, None);

// Record a histogram value (e.g., latency)
let mut tags = HashMap::new();
tags.insert("method".to_string(), "verify".to_string());
record_histogram("jacs_operation_duration_ms", 150.0, Some(tags));
```

### Built-in Metrics

When `observability-convenience` feature is enabled, JACS automatically records:

- `jacs_agent_operations` - Count of agent operations
- `jacs_signature_verifications` - Signature verification results
- `jacs_document_operations` - Document create/update/verify counts

## Distributed Tracing

### Enabling Tracing

```rust
use jacs::{TracingConfig, TracingDestination, SamplingConfig, ResourceConfig};
use std::collections::HashMap;

let config = ObservabilityConfig {
    // ... logs and metrics config ...
    tracing: Some(TracingConfig {
        enabled: true,
        sampling: SamplingConfig {
            ratio: 1.0,           // Sample all traces
            parent_based: true,
            rate_limit: None,
        },
        resource: Some(ResourceConfig {
            service_name: "my-jacs-app".to_string(),
            service_version: Some("1.0.0".to_string()),
            environment: Some("production".to_string()),
            attributes: HashMap::new(),
        }),
        destination: Some(TracingDestination::Otlp {
            endpoint: "http://localhost:4318".to_string(),
            headers: None,
        }),
    }),
};
```

### Tracing Destinations

#### OTLP

```rust
TracingDestination::Otlp {
    endpoint: "http://localhost:4318".to_string(),
    headers: None,
}
```

#### Jaeger

```rust
TracingDestination::Jaeger {
    endpoint: "http://localhost:14268/api/traces".to_string(),
    headers: None,
}
```

### Sampling Configuration

Control how many traces are captured:

```rust
SamplingConfig {
    ratio: 0.1,          // Sample 10% of traces
    parent_based: true,  // Inherit parent sampling decision
    rate_limit: Some(100), // Max 100 samples per second
}
```

### Using Tracing Spans

```rust
use tracing::{instrument, info_span};

#[instrument]
fn sign_document(doc: &Document) -> Result<(), Error> {
    // Automatically creates a span named "sign_document"
    // with doc as a field
}

fn manual_span() {
    let span = info_span!("verify_chain", doc_count = 5);
    let _guard = span.enter();

    // Operations within this span
}
```

## Configuration File

You can configure observability via `jacs.config.json`:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info",
      "destination": {
        "file": {
          "path": "./logs"
        }
      }
    },
    "metrics": {
      "enabled": true,
      "destination": {
        "otlp": {
          "endpoint": "http://localhost:4318"
        }
      },
      "export_interval_seconds": 30
    },
    "tracing": {
      "enabled": true,
      "sampling": {
        "ratio": 1.0,
        "parent_based": true
      },
      "resource": {
        "service_name": "jacs-service",
        "service_version": "1.0.0",
        "environment": "production"
      },
      "destination": {
        "otlp": {
          "endpoint": "http://localhost:4318"
        }
      }
    }
  }
}
```

## OpenTelemetry Collector Setup

For production use, route telemetry through an OpenTelemetry Collector:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  logging:
    loglevel: debug
  prometheus:
    endpoint: "0.0.0.0:9090"
  jaeger:
    endpoint: jaeger:14250

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [logging]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus]
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger]
```

## Reset and Cleanup

For testing or reinitialization:

```rust
use jacs::observability::{reset_observability, flush_observability, force_reset_for_tests};

// Flush pending data
flush_observability();

// Reset configuration
reset_observability();

// Force reset for tests (clears all state)
force_reset_for_tests();
```

## Best Practices

### Development

```rust
let config = ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "debug".to_string(),
        destination: LogDestination::Stderr,
        headers: None,
    },
    metrics: MetricsConfig {
        enabled: false,
        destination: MetricsDestination::Stdout,
        export_interval_seconds: None,
        headers: None,
    },
    tracing: None,
};
```

### Production

```rust
let config = ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "info".to_string(),
        destination: LogDestination::Otlp {
            endpoint: "http://collector:4318".to_string(),
            headers: Some(auth_headers()),
        },
        headers: None,
    },
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Otlp {
            endpoint: "http://collector:4318".to_string(),
            headers: Some(auth_headers()),
        },
        export_interval_seconds: Some(30),
        headers: None,
    },
    tracing: Some(TracingConfig {
        enabled: true,
        sampling: SamplingConfig {
            ratio: 0.1,  // Sample 10% in production
            parent_based: true,
            rate_limit: Some(1000),
        },
        resource: Some(ResourceConfig {
            service_name: "jacs-production".to_string(),
            service_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            environment: Some("production".to_string()),
            attributes: HashMap::new(),
        }),
        destination: Some(TracingDestination::Otlp {
            endpoint: "http://collector:4318".to_string(),
            headers: Some(auth_headers()),
        }),
    }),
};
```

## Troubleshooting

### Logs Not Appearing

1. Check that logging is enabled: `logs.enabled: true`
2. Verify log level includes your log statements
3. For file logging, ensure the directory is writable

### Metrics Not Exporting

1. Verify `otlp-metrics` feature is enabled
2. Check endpoint connectivity
3. Confirm metrics are enabled: `metrics.enabled: true`

### Traces Missing

1. Verify `otlp-tracing` feature is enabled
2. Check sampling ratio isn't filtering all traces
3. Ensure spans are properly instrumented

## Next Steps

- [Rust Library API](library.md) - Use observability in your code
- [Configuration Reference](../reference/configuration.md) - Full config options
- [Advanced Topics](../advanced/security.md) - Security considerations
