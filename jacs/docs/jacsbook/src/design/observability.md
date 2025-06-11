# JACS Observability Guide

The JACS library includes a comprehensive observability system built on `tracing` and `metrics` crates, providing structured logging, metrics collection, and distributed tracing for agent operations.

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
- File-based logging at INFO level in `./logs/`
- File-based metrics in `./metrics.txt`
- 60-second metrics export interval
- Tracing disabled by default

### 2. Custom Configuration

For more control, use custom configuration:

```rust
use jacs::{init_custom_observability, ObservabilityConfig, LogConfig, MetricsConfig, 
           TracingConfig, SamplingConfig, LogDestination, MetricsDestination};
use std::collections::HashMap;

let config = ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "debug".to_string(),
        destination: LogDestination::File {
            path: "./custom_logs".to_string(),
        },
        headers: None,
    },
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Prometheus {
            endpoint: "http://localhost:9090".to_string(),
            headers: None,
        },
        export_interval_seconds: Some(30),
        headers: None,
    },
    tracing: Some(TracingConfig {
        enabled: true,
        sampling: SamplingConfig {
            ratio: 0.1, // Sample 10% of traces
            parent_based: true,
            rate_limit: Some(100), // Max 100 samples per second
        },
        resource: None,
    }),
};

init_custom_observability(config)?;
```

## Configuration Reference

### ObservabilityConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `logs` | `LogConfig` | Logging configuration | See LogConfig defaults |
| `metrics` | `MetricsConfig` | Metrics configuration | See MetricsConfig defaults |
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

### TracingConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `enabled` | `bool` | Enable/disable distributed tracing | Required |
| `sampling` | `SamplingConfig` | Sampling configuration | See SamplingConfig |
| `resource` | `Option<ResourceConfig>` | Service resource information | `None` |

### SamplingConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `ratio` | `f64` | Sampling ratio (0.0 to 1.0) | `1.0` (100%) |
| `parent_based` | `bool` | Use parent span sampling decision | `true` |
| `rate_limit` | `Option<u32>` | Maximum samples per second | `None` |

### ResourceConfig

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

// OpenTelemetry Protocol (OTLP) with optional headers
LogDestination::Otlp { 
    endpoint: "http://jaeger:4317".to_string(),
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

// Prometheus with optional authentication
MetricsDestination::Prometheus { 
    endpoint: "http://prometheus:9090".to_string(),
    headers: Some({
        let mut h = HashMap::new();
        h.insert("Authorization".to_string(), "Basic dXNlcjpwYXNz".to_string());
        h
    }),
}

// OpenTelemetry Protocol (OTLP)
MetricsDestination::Otlp { 
    endpoint: "http://otel-collector:4317".to_string(),
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

## Distributed Tracing

Enable distributed tracing to track requests across service boundaries:

```rust
use jacs::{ObservabilityConfig, TracingConfig, SamplingConfig, ResourceConfig};
use std::collections::HashMap;

let config = ObservabilityConfig {
    logs: LogConfig::default(),
    metrics: MetricsConfig::default(),
    tracing: Some(TracingConfig {
        enabled: true,
        sampling: SamplingConfig {
            ratio: 0.1,           // Sample 10% of traces
            parent_based: true,   // Respect parent sampling decisions
            rate_limit: Some(100), // Max 100 traces/second
        },
        resource: Some(ResourceConfig {
            service_name: "jacs-agent".to_string(),
            service_version: Some("1.0.0".to_string()),
            environment: Some("production".to_string()),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("team".to_string(), "platform".to_string());
                attrs
            },
        }),
    }),
};
```

## Authentication & Headers

For secure endpoints, use headers for authentication:

```rust
use std::collections::HashMap;

// API Key authentication
let mut headers = HashMap::new();
headers.insert("X-API-Key".to_string(), "your-api-key".to_string());

// Bearer token authentication
let mut headers = HashMap::new();
headers.insert("Authorization".to_string(), "Bearer your-jwt-token".to_string());

// Basic authentication
let mut headers = HashMap::new();
headers.insert("Authorization".to_string(), "Basic dXNlcjpwYXNzd29yZA==".to_string());

// Use in configuration
let config = ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "info".to_string(),
        destination: LogDestination::Otlp {
            endpoint: "https://api.honeycomb.io/v1/traces".to_string(),
            headers: Some(headers),
        },
        headers: None,
    },
    // ... rest of config
};
```

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
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Stdout,
        export_interval_seconds: None,
        headers: None,
    },
    tracing: None, // Disabled for development
}
```

### Production with External Services
```rust
ObservabilityConfig {
    logs: LogConfig {
        enabled: true,
        level: "info".to_string(),
        destination: LogDestination::Otlp {
            endpoint: "http://jaeger:4317".to_string(),
            headers: Some({
                let mut h = HashMap::new();
                h.insert("Authorization".to_string(), "Bearer prod-token".to_string());
                h
            }),
        },
        headers: None,
    },
    metrics: MetricsConfig {
        enabled: true,
        destination: MetricsDestination::Prometheus {
            endpoint: "http://prometheus:9090".to_string(),
            headers: None,
        },
        export_interval_seconds: Some(60),
        headers: None,
    },
    tracing: Some(TracingConfig {
        enabled: true,
        sampling: SamplingConfig {
            ratio: 0.01, // 1% sampling in production
            parent_based: true,
            rate_limit: Some(1000),
        },
        resource: Some(ResourceConfig {
            service_name: "jacs-production".to_string(),
            service_version: Some("2.1.0".to_string()),
            environment: Some("production".to_string()),
            attributes: HashMap::new(),
        }),
    }),
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
        headers: None,
    },
    metrics: MetricsConfig {
        enabled: false, // Disable metrics in tests
        destination: MetricsDestination::Stdout,
        export_interval_seconds: None,
        headers: None,
    },
    tracing: None, // Usually disabled in unit tests
}
```

## Integration with Configuration Files

Add observability to your `jacs.config.json`:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
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
        "prometheus": {
          "endpoint": "http://localhost:9090",
          "headers": {
            "Authorization": "Bearer your-token"
          }
        }
      },
      "export_interval_seconds": 30
    },
    "tracing": {
      "enabled": true,
      "sampling": {
        "ratio": 0.1,
        "parent_based": true,
        "rate_limit": 100
      },
      "resource": {
        "service_name": "my-jacs-service",
        "service_version": "1.0.0",
        "environment": "production"
      }
    }
  }
}
```

## Best Practices

1. **Initialize Early**: Call the initialization function as early as possible in your application
2. **Use Appropriate Log Levels**: 
   - `error!` for actual errors that need attention
   - `warn!` for concerning but non-fatal issues
   - `info!` for important application events
   - `debug!` for detailed diagnostic information
   - `trace!` for very verbose debugging
3. **Include Context**: Add relevant context to your logs (agent IDs, operation types, etc.)
4. **Use Convenience Functions**: Prefer the domain-specific convenience functions for agent operations
5. **Tag Your Metrics**: Always include relevant tags for better filtering and aggregation
6. **Sample Traces in Production**: Use sampling to reduce overhead (1-10% is typical)
7. **Secure Your Endpoints**: Use headers for authentication when sending to external services
8. **Set Resource Information**: Properly identify your service in tracing data

## Troubleshooting

- **Global Subscriber Already Set**: If you see this error, it means observability was already initialized. This is usually fine in production.
- **File Permission Errors**: Ensure the application has write permissions to the log/metrics directories
- **Missing Log Output**: Check that the log level is appropriate for your messages
- **Empty Metrics File**: Ensure sufficient time has passed for the export interval, or call flush explicitly
- **Authentication Failures**: Verify your headers and credentials for external endpoints
- **High Overhead**: Reduce tracing sampling ratio or increase rate limits

## Run the Example

```bash
cargo run --example observability_demo
```

This will create log files in `./logs/` and metrics in `./metrics.txt` that you can inspect. 