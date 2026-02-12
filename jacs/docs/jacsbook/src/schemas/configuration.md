# Config File Schema

This page documents the `jacs.config.json` schema fields. For a comprehensive configuration guide including observability setup, storage backends, zero-config quickstart, and production patterns, see the [Configuration Reference](../reference/configuration.md).

## Schema Location

```
https://hai.ai/schemas/jacs.config.schema.json
```

## Minimal Configuration

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_agent_id_and_version": "YOUR_AGENT_ID:YOUR_VERSION",
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

All other settings use sensible defaults (`./jacs_data`, `./jacs_keys`, `fs` storage). Override only what you need.

## Fields

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

## Observability Fields

The `observability` object supports `logs`, `metrics`, and `tracing` sub-objects. For full details on all destinations, sampling options, and production patterns, see the [Configuration Reference](../reference/configuration.md#observability-configuration).

## Environment Variables

Configuration can be overridden with environment variables:

| Variable | Config Field |
|----------|--------------|
| `JACS_PRIVATE_KEY_PASSWORD` | `jacs_private_key_password` |
| `JACS_DATA_DIRECTORY` | `jacs_data_directory` |
| `JACS_KEY_DIRECTORY` | `jacs_key_directory` |

## See Also

- [Configuration Reference](../reference/configuration.md) - Full configuration guide with examples
- [JSON Schemas Overview](overview.md) - Schema architecture
- [Observability (Rust API)](../rust/observability.md) - Rust observability API
- [Observability & Monitoring Guide](../guides/observability.md) - Structured events, OTEL collector setup
