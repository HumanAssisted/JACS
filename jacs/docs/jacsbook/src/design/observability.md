# JACS Observability Guide

The JACS library includes a comprehensive observability system built on `tracing` and `metrics` crates, providing structured logging and metrics collection for agent operations.

## Quick Start

### 1. Initialize Observability

The easiest way to get started is to use the default configuration:

```rust
use jacs::init_default_observability;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with sensible defaults
    init_default_observability()?;
    
    // Your application code here...
    
    Ok(())
}
```

This sets up:
- File-based logging at INFO level in `./logs/app.log.*`
- File-based metrics in `./metrics.txt`
- 60-second metrics export interval

### 2. Custom Configuration

For more control, use custom configuration:

```rust
use jacs::{init_custom_observability, ObservabilityConfig, LogConfig, MetricsConfig, LogDestination, MetricsDestination};

let config = ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "debug".to_string(),
        destination: LogDestination::File {
            path: "./custom_logs".to_string(),
        },
    },
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Prometheus {
            endpoint: "http://localhost:9090".to_string(),
        },
        export_interval_seconds: Some(30),
    },
};

init_custom_observability(config)?;
```

## Logging

### Standard Tracing Macros

Use standard `tracing` macros for general application logging:

```rust
use tracing::{info, debug, warn, error};

info!("Agent operation completed successfully");
debug!("Processing document: {}", document_id);
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

The system automatically records metrics for:
- Agent operation counts and durations
- Document validation success/failure rates
- Signature verification success/failure rates

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

## Destinations

### Log Destinations

- **File**: Logs to rotating daily files
- **Stderr**: Logs to standard error
- **OTLP**: Exports to OpenTelemetry Protocol endpoint
- **Null**: Disables logging

### Metrics Destinations

- **File**: Exports metrics to text file
- **Prometheus**: Exports to Prometheus endpoint
- **OTLP**: Exports to OpenTelemetry Protocol endpoint
- **Stdout**: Prints metrics to standard output

## Example Configuration for Different Environments

### Development
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "debug".to_string(),
        destination: LogDestination::Stderr,
    },
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Stdout,
        export_interval_seconds: None,
    },
}
```

### Production
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "info".to_string(),
        destination: LogDestination::OTLP {
            endpoint: "http://jaeger:4317".to_string(),
        },
    },
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Prometheus {
            endpoint: "http://prometheus:9090".to_string(),
        },
        export_interval_seconds: Some(60),
    },
}
```

### Testing
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "trace".to_string(),
        destination: LogDestination::File {
            path: "./test_logs".to_string(),
        },
    },
    metrics: MetricsConfig {
        enabled: false,
        destination: MetricsDestination::Stdout,
        export_interval_seconds: None,
    },
}
```

## Best Practices

1. **Initialize Early**: Call the initialization function as early as possible in your application
2. **Use Appropriate Log Levels**: 
   - `error!` for actual errors
   - `warn!` for concerning but non-fatal issues
   - `info!` for important application events
   - `debug!` for detailed diagnostic information
3. **Include Context**: Add relevant context to your logs (agent IDs, operation types, etc.)
4. **Use Convenience Functions**: Prefer the domain-specific convenience functions for agent operations
5. **Tag Your Metrics**: Always include relevant tags for better filtering and aggregation

## Troubleshooting

- **Global Subscriber Already Set**: If you see this error, it means observability was already initialized. This is usually fine in production.
- **File Permission Errors**: Ensure the application has write permissions to the log/metrics directories
- **Missing Log Output**: Check that the log level is appropriate for your messages
- **Empty Metrics File**: Ensure sufficient time has passed for the export interval, or call flush explicitly

## Run the Example

```bash
cargo run --example observability_demo
```

This will create log files in `./logs/` and metrics in `./metrics.txt` that you can inspect. 