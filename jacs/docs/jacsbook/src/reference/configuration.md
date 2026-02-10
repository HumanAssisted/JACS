# Configuration Reference

## Overview

### Key resolution for verifiers

When verifying signed documents, JACS resolves the signer’s public key using a configurable order of sources. Set **`JACS_KEY_RESOLUTION`** (environment variable or in config) to a comma-separated list of sources: `local` (trust store), `dns` (DNS TXT record), `hai` (HAI key service). Example: `JACS_KEY_RESOLUTION=local,hai` or `local,dns,hai`. The first source that returns a key for the signer’s ID is used. Use `verify_standalone()` with explicit `keyResolution` for one-off verification without loading a full config.

## Zero-Config Path

If you just want to sign and verify without any configuration, use `quickstart()`:

```python
import jacs.simple as jacs
jacs.quickstart()  # No config file needed
```

```javascript
const jacs = require('@hai.ai/jacs/simple');
jacs.quickstart();  // No config file needed
```

```bash
jacs quickstart  # CLI -- no config file needed
```

`quickstart()` creates an ephemeral agent with keys in memory. No files are written to disk.

## Minimal Configuration

For persistent agents, a config file needs only two fields (plus `$schema`):

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_agent_id_and_version": "YOUR_AGENT_ID:YOUR_VERSION",
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

All other settings use sensible defaults (`./jacs_data`, `./jacs_keys`, `fs` storage). Override only what you need.

## Complete Example Configuration

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_use_security": "false",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "jacs.private.pem.enc",
  "jacs_agent_public_key_filename": "jacs.public.pem",
  "jacs_agent_key_algorithm": "RSA-PSS",
  "jacs_default_storage": "fs",
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info",
      "destination": {
        "type": "file",
        "path": "./logs"
      },
      "headers": {
        "Authorization": "Bearer token",
        "X-API-Key": "secret"
      }
    },
    "metrics": {
      "enabled": true,
      "destination": {
        "type": "prometheus",
        "endpoint": "http://localhost:9090/api/v1/write",
        "headers": {
          "Authorization": "Basic dXNlcjpwYXNz"
        }
      },
      "export_interval_seconds": 60,
      "headers": {
        "X-Service": "jacs"
      }
    },
    "tracing": {
      "enabled": true,
      "sampling": {
        "ratio": 0.1,
        "parent_based": true,
        "rate_limit": 100
      },
      "resource": {
        "service_name": "jacs",
        "service_version": "0.4.0",
        "environment": "production",
        "attributes": {
          "team": "platform",
          "region": "us-west-2"
        }
      }
    }
  }
}
```

## Observability Configuration

JACS supports comprehensive observability through configurable logging, metrics, and tracing. All observability features are optional and can be configured in the `jacs.config.json` file.

### Logs Configuration

Controls how JACS generates and outputs log messages.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | Yes | Whether logging is enabled |
| `level` | string | Yes | Minimum log level: `trace`, `debug`, `info`, `warn`, `error` |
| `destination` | object | Yes | Where logs are sent (see destinations below) |
| `headers` | object | No | Additional headers for remote destinations |

#### Log Destinations

**File Logging**
```json
{
  "type": "file",
  "path": "./logs"
}
```
Writes logs to rotating files in the specified directory.

**Console Logging (stderr)**
```json
{
  "type": "stderr"
}
```
Outputs logs to standard error stream.

**OpenTelemetry Protocol (OTLP)**
```json
{
  "type": "otlp",
  "endpoint": "http://localhost:4317",
  "headers": {
    "Authorization": "Bearer token"
  }
}
```
Sends logs to an OTLP-compatible endpoint (like Jaeger, Grafana Cloud).

**Null (disabled)**
```json
{
  "type": "null"
}
```
Discards all log output.

### Metrics Configuration

Controls collection and export of application metrics.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | Yes | Whether metrics collection is enabled |
| `destination` | object | Yes | Where metrics are exported (see destinations below) |
| `export_interval_seconds` | integer | No | How often to export metrics (default: 60) |
| `headers` | object | No | Additional headers for remote destinations |

#### Metrics Destinations

**Prometheus Remote Write**
```json
{
  "type": "prometheus",
  "endpoint": "http://localhost:9090/api/v1/write",
  "headers": {
    "Authorization": "Basic dXNlcjpwYXNz"
  }
}
```
Exports metrics in Prometheus format to a remote write endpoint.

**OpenTelemetry Protocol (OTLP)**
```json
{
  "type": "otlp",
  "endpoint": "http://localhost:4317",
  "headers": {
    "Authorization": "Bearer token"
  }
}
```
Exports metrics to an OTLP-compatible endpoint.

**File Export**
```json
{
  "type": "file",
  "path": "./metrics.txt"
}
```
Writes metrics to a local file.

**Console Output (stdout)**
```json
{
  "type": "stdout"
}
```
Prints metrics to standard output.

### Tracing Configuration

Controls distributed tracing for request flows.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | Yes | Whether tracing is enabled |
| `sampling` | object | No | Sampling configuration (see below) |
| `resource` | object | No | Service identification (see below) |

#### Sampling Configuration

Controls which traces are collected to manage overhead.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ratio` | number | 1.0 | Fraction of traces to sample (0.0-1.0) |
| `parent_based` | boolean | true | Whether to respect parent trace sampling decisions |
| `rate_limit` | integer | none | Maximum traces per second |

**Examples:**
- `"ratio": 1.0` - Sample all traces (100%)
- `"ratio": 0.1` - Sample 10% of traces
- `"ratio": 0.01` - Sample 1% of traces
- `"rate_limit": 10` - Maximum 10 traces per second

#### Resource Configuration

Identifies the service in distributed tracing systems.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service_name` | string | Yes | Name of the service |
| `service_version` | string | No | Version of the service |
| `environment` | string | No | Environment (dev, staging, prod) |
| `attributes` | object | No | Custom key-value attributes |

## Authentication & Headers

For remote destinations (OTLP, Prometheus), you can specify authentication headers:

**Bearer Token Authentication:**
```json
"headers": {
  "Authorization": "Bearer your-token-here"
}
```

**Basic Authentication:**
```json
"headers": {
  "Authorization": "Basic dXNlcjpwYXNz"
}
```

**API Key Authentication:**
```json
"headers": {
  "X-API-Key": "your-api-key",
  "X-Auth-Token": "your-auth-token"
}
```

## Common Patterns

### Development Configuration
```json
"observability": {
  "logs": {
    "enabled": true,
    "level": "debug",
    "destination": { "type": "stderr" }
  },
  "metrics": {
    "enabled": true,
    "destination": { "type": "stdout" }
  }
}
```

### Production Configuration
```json
"observability": {
  "logs": {
    "enabled": true,
    "level": "info",
    "destination": {
      "type": "otlp",
      "endpoint": "https://logs.example.com:4317",
      "headers": {
        "Authorization": "Bearer prod-token"
      }
    }
  },
  "metrics": {
    "enabled": true,
    "destination": {
      "type": "prometheus",
      "endpoint": "https://metrics.example.com/api/v1/write"
    },
    "export_interval_seconds": 30
  },
  "tracing": {
    "enabled": true,
    "sampling": {
      "ratio": 0.05,
      "rate_limit": 100
    },
    "resource": {
      "service_name": "jacs",
      "service_version": "0.4.0",
      "environment": "production"
    }
  }
}
```

### File-based Configuration
```json
"observability": {
  "logs": {
    "enabled": true,
    "level": "info",
    "destination": {
      "type": "file",
      "path": "/var/log/jacs"
    }
  },
  "metrics": {
    "enabled": true,
    "destination": {
      "type": "file",
      "path": "/var/log/jacs/metrics.txt"
    },
    "export_interval_seconds": 60
  }
}
```

## Environment Variable Integration

The observability configuration works alongside JACS's core configuration system. 

### Required Environment Variable

Only **one** environment variable is truly required:

- `JACS_PRIVATE_KEY_PASSWORD` - Password for encrypting/decrypting private keys (required for cryptographic operations)

### Configuration-Based Settings

All other JACS settings are **configuration file fields** that have sensible defaults:

- `jacs_data_directory` - Where agent/document data is stored (default: `./jacs_data`)
- `jacs_key_directory` - Where cryptographic keys are stored (default: `./jacs_keys`)
- `jacs_agent_key_algorithm` - Cryptographic algorithm to use (default: `RSA-PSS`)
- `jacs_default_storage` - Storage backend (default: `fs`)
- `jacs_use_security` / `JACS_ENABLE_FILESYSTEM_QUARANTINE` - Enable filesystem quarantine of executable files (default: `false`). The env var `JACS_USE_SECURITY` is deprecated; use `JACS_ENABLE_FILESYSTEM_QUARANTINE` instead.

These can be overridden by environment variables if needed, but they are primarily configured through the `jacs.config.json` file.

The observability configuration is completely optional - JACS will work without any observability configuration.

## Storage Configuration

The `jacs_default_storage` field determines where JACS stores agent data, documents, and keys. This is a critical configuration that affects how your data is persisted and accessed.

### Available Storage Backends

| Backend | Value | Description | Use Case |
|---------|-------|-------------|----------|
| **Filesystem** | `"fs"` | Local file system storage | Development, single-node deployments |
| **AWS S3** | `"aws"` | Amazon S3 object storage | Production, cloud deployments |
| **HAI Remote** | `"hai"` | HAI.ai remote storage service | HAI.ai platform integration |
| **Memory** | `"memory"` | In-memory storage (non-persistent) | Testing, temporary data |
| **Web Local** | `"local"` | Browser local storage (WASM only) | Web applications |

### Backend-Specific Configuration

#### Filesystem Storage (`"fs"`)
```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys"
}
```

**Requirements:** None - works out of the box
**Data location:** Local directories as specified in config
**Best for:** Development, local testing, single-machine deployments

#### AWS S3 Storage (`"aws"`)
```json
{
  "jacs_default_storage": "aws"
}
```

**Required Environment Variables:**
- `JACS_ENABLE_AWS_BUCKET_NAME` - S3 bucket name
- `AWS_ACCESS_KEY_ID` - AWS access key
- `AWS_SECRET_ACCESS_KEY` - AWS secret key
- `AWS_REGION` - AWS region (optional, defaults to us-east-1)

**Best for:** Production deployments, distributed systems, cloud-native applications

#### HAI Remote Storage (`"hai"`)
```json
{
  "jacs_default_storage": "hai"
}
```

**Required Environment Variables:**
- `HAI_STORAGE_URL` - HAI.ai storage service endpoint

**Best for:** Integration with HAI.ai platform services

#### Memory Storage (`"memory"`)
```json
{
  "jacs_default_storage": "memory"
}
```

**Requirements:** None
**Data persistence:** None - data is lost when application stops
**Best for:** Unit testing, temporary operations, development scenarios

### Storage Behavior

- **Agent data** (agent definitions, signatures) are stored using the configured backend
- **Documents** are stored using the configured backend
- **Cryptographic keys** are stored using the configured backend
- **Observability data** (logs, metrics) can use separate storage via observability configuration

### Configuration Examples

**Development Setup (Filesystem)**
```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./dev_data",
  "jacs_key_directory": "./dev_keys"
}
```

**Production Setup (AWS S3)**
```json
{
  "jacs_default_storage": "aws"
}
```

With environment variables:
```bash
export JACS_ENABLE_AWS_BUCKET_NAME="my-jacs-production-bucket"
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-west-2"
```

**HAI Platform Integration**
```json
{
  "jacs_default_storage": "hai"
}
```

With environment variable:
```bash
export HAI_STORAGE_URL="https://storage.hai.ai/v1"
```

### Security Considerations

- **AWS S3**: Ensure proper IAM permissions for bucket access
- **HAI Remote**: Secure the `HAI_STORAGE_URL` endpoint and any required authentication
- **Filesystem**: Ensure proper file system permissions for data and key directories
- **Keys**: Regardless of storage backend, always set `JACS_PRIVATE_KEY_PASSWORD` for key encryption

### Migration Between Storage Backends

When changing storage backends, you'll need to:

1. Export existing data from the current backend
2. Update the `jacs_default_storage` configuration
3. Set any required environment variables for the new backend
4. Import data into the new backend

JACS doesn't automatically migrate data between storage backends - this must be done manually or via custom scripts.
