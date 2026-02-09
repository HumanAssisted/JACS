# Configuration

The JACS configuration file (`jacs.config.json`) defines agent settings, key locations, storage backends, and observability options.

## Schema Location

```
https://hai.ai/schemas/jacs.config.schema.json
```

## Quick Start

Create a minimal configuration file:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "private.pem",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_default_storage": "fs"
}
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacs_data_directory` | string | Path to store documents and agents |
| `jacs_key_directory` | string | Path to store cryptographic keys |
| `jacs_agent_private_key_filename` | string | Private key filename |
| `jacs_agent_public_key_filename` | string | Public key filename |
| `jacs_agent_key_algorithm` | string | Signing algorithm |
| `jacs_default_storage` | string | Storage backend |

## Configuration Options

### Key Configuration

#### jacs_agent_key_algorithm

Specifies the cryptographic algorithm for signing:

| Value | Description |
|-------|-------------|
| `ring-Ed25519` | Ed25519 signatures (recommended) |
| `RSA-PSS` | RSA with PSS padding |
| `pq-dilithium` | Post-quantum Dilithium |
| `pq2025` | Post-quantum composite |

```json
{
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

#### jacs_agent_private_key_filename

Name of the private key file in the key directory:

```json
{
  "jacs_agent_private_key_filename": "private.pem"
}
```

If the key is encrypted, it will have `.enc` appended automatically when loading.

#### jacs_agent_public_key_filename

Name of the public key file:

```json
{
  "jacs_agent_public_key_filename": "public.pem"
}
```

#### jacs_private_key_password

Password for encrypted private keys:

```json
{
  "jacs_private_key_password": "your-password"
}
```

**Warning**: Do not store passwords in config files for production. Use the `JACS_PRIVATE_KEY_PASSWORD` environment variable instead.

### Storage Configuration

#### jacs_default_storage

Specifies where documents are stored:

| Value | Description |
|-------|-------------|
| `fs` | Local filesystem |
| `aws` | AWS S3 storage |
| `hai` | HAI cloud storage |

```json
{
  "jacs_default_storage": "fs"
}
```

#### jacs_data_directory

Path for storing documents and agents:

```json
{
  "jacs_data_directory": "./jacs_data"
}
```

### Agent Identity

#### jacs_agent_id_and_version

Load an existing agent by ID and version:

```json
{
  "jacs_agent_id_and_version": "550e8400-e29b-41d4-a716-446655440000:f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

### Schema Versions

Specify which schema versions to use:

```json
{
  "jacs_agent_schema_version": "v1",
  "jacs_header_schema_version": "v1",
  "jacs_signature_schema_version": "v1"
}
```

### DNS Configuration

For DNSSEC-based agent verification:

#### jacs_agent_domain

Domain for DNS-based public key verification:

```json
{
  "jacs_agent_domain": "example.com"
}
```

#### jacs_dns_validate

Enable DNS TXT fingerprint validation:

```json
{
  "jacs_dns_validate": true
}
```

#### jacs_dns_strict

Require DNSSEC validation (no fallback):

```json
{
  "jacs_dns_strict": true
}
```

#### jacs_dns_required

Require domain and DNS validation:

```json
{
  "jacs_dns_required": true
}
```

### Security

#### jacs_use_security

Enable strict security features:

```json
{
  "jacs_use_security": "1"
}
```

Values: `"0"`, `"1"`, or `"false"`, `"true"`

## Observability Configuration

JACS supports comprehensive observability through logs, metrics, and tracing.

### Logs Configuration

```json
{
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info",
      "destination": {
        "type": "stderr"
      }
    }
  }
}
```

#### Log Levels

| Level | Description |
|-------|-------------|
| `trace` | Most verbose |
| `debug` | Debug information |
| `info` | General information |
| `warn` | Warnings |
| `error` | Errors only |

#### Log Destinations

**stderr** (default):
```json
{
  "destination": { "type": "stderr" }
}
```

**File**:
```json
{
  "destination": {
    "type": "file",
    "path": "/var/log/jacs/app.log"
  }
}
```

**OTLP** (OpenTelemetry):
```json
{
  "destination": {
    "type": "otlp",
    "endpoint": "http://localhost:4317",
    "headers": {
      "Authorization": "Bearer token"
    }
  }
}
```

**Null** (disabled):
```json
{
  "destination": { "type": "null" }
}
```

### Metrics Configuration

```json
{
  "observability": {
    "metrics": {
      "enabled": true,
      "destination": {
        "type": "prometheus",
        "endpoint": "http://localhost:9090/api/v1/write"
      },
      "export_interval_seconds": 60
    }
  }
}
```

#### Metrics Destinations

**Prometheus**:
```json
{
  "destination": {
    "type": "prometheus",
    "endpoint": "http://localhost:9090/api/v1/write"
  }
}
```

**OTLP**:
```json
{
  "destination": {
    "type": "otlp",
    "endpoint": "http://localhost:4317"
  }
}
```

**File**:
```json
{
  "destination": {
    "type": "file",
    "path": "/var/log/jacs/metrics.json"
  }
}
```

**stdout**:
```json
{
  "destination": { "type": "stdout" }
}
```

### Tracing Configuration

```json
{
  "observability": {
    "tracing": {
      "enabled": true,
      "sampling": {
        "ratio": 0.1,
        "parent_based": true,
        "rate_limit": 100
      },
      "resource": {
        "service_name": "my-jacs-agent",
        "service_version": "1.0.0",
        "environment": "production",
        "attributes": {
          "team": "backend"
        }
      }
    }
  }
}
```

#### Sampling Options

| Field | Type | Description |
|-------|------|-------------|
| `ratio` | number (0-1) | Percentage of traces to sample |
| `parent_based` | boolean | Follow parent span's sampling decision |
| `rate_limit` | integer | Max traces per second |

## Complete Configuration Example

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",

  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "private.pem",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_default_storage": "fs",

  "jacs_agent_schema_version": "v1",
  "jacs_header_schema_version": "v1",
  "jacs_signature_schema_version": "v1",

  "jacs_agent_domain": "myagent.example.com",
  "jacs_dns_validate": true,
  "jacs_dns_strict": false,

  "observability": {
    "logs": {
      "enabled": true,
      "level": "info",
      "destination": {
        "type": "file",
        "path": "/var/log/jacs/agent.log"
      }
    },
    "metrics": {
      "enabled": true,
      "destination": {
        "type": "prometheus",
        "endpoint": "http://prometheus:9090/api/v1/write"
      },
      "export_interval_seconds": 30
    },
    "tracing": {
      "enabled": true,
      "sampling": {
        "ratio": 0.1,
        "parent_based": true
      },
      "resource": {
        "service_name": "jacs-agent",
        "service_version": "1.0.0",
        "environment": "production"
      }
    }
  }
}
```

## Environment Variables

Configuration can be overridden with environment variables:

| Variable | Config Field |
|----------|--------------|
| `JACS_PRIVATE_KEY_PASSWORD` | `jacs_private_key_password` |
| `JACS_DATA_DIRECTORY` | `jacs_data_directory` |
| `JACS_KEY_DIRECTORY` | `jacs_key_directory` |

```bash
export JACS_PRIVATE_KEY_PASSWORD="secure-password"
```

## Loading Configuration

### Python

```python
import jacs

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')
```

### Node.js

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
agent.load('./jacs.config.json');
```

### CLI

```bash
jacs --config ./jacs.config.json agent show
```

## Production Best Practices

1. **Never commit private keys** - Keep keys out of version control
2. **Use environment variables for secrets** - Don't store passwords in config files
3. **Enable observability** - Configure logs and metrics for monitoring
4. **Use DNS validation** - Enable `jacs_dns_validate` for additional security
5. **Secure key directories** - Restrict file permissions on key directories

```bash
chmod 700 ./jacs_keys
chmod 600 ./jacs_keys/private.pem
```

## See Also

- [JSON Schemas Overview](overview.md) - Schema architecture
- [Observability](../rust/observability.md) - Monitoring guide
- [DNS Verification](../dns.md) - Domain-based verification
- [Quick Start](../getting-started/quickstart.md) - Getting started guide
