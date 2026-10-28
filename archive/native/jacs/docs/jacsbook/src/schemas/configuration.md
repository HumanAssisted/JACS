# Config File Schema

This page documents the `jacs.config.json` schema fields. For a comprehensive configuration guide including observability setup, storage backends, zero-config quickstart, and production patterns, see the [Configuration Reference](../reference/configuration.md).

## Schema Location

```
https://hai.ai/schemas/jacs.config.schema.json
```

## Minimal Configuration

Use `quickstart()` to create and sign a persistent config. A creation template
must include the schema's six required settings:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_private_key_filename": "jacs.private.pem.enc",
  "jacs_agent_public_key_filename": "jacs.public.pem",
  "jacs_agent_key_algorithm": "pq2025",
  "jacs_default_storage": "fs"
}
```

This unsigned template does not load an existing identity. Existing-agent
configs also need the generated identity/version and valid config signature;
do not reconstruct them by editing this template.

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacs_data_directory` | string | Path to store documents and agents |
| `jacs_key_directory` | string | Path to store cryptographic keys |
| `jacs_agent_private_key_filename` | string | Private key filename |
| `jacs_agent_public_key_filename` | string | Public key filename |
| `jacs_agent_key_algorithm` | string | Signing algorithm |
| `jacs_default_storage` | string | Storage backend |
| `jacs_keychain_backend` | string | OS keychain backend: `"auto"`, `"macos-keychain"`, `"linux-secret-service"`, `"disabled"` |

## Configuration Options

### Key Configuration

#### jacs_agent_key_algorithm

Specifies the cryptographic algorithm for signing:

| Value | Description |
|-------|-------------|
| `ring-Ed25519` | Ed25519 signatures (explicit compatibility) |
| `pq2025` | FIPS-204 ML-DSA-87 post-quantum signatures |

```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

#### jacs_agent_private_key_filename

Name of the private key file in the key directory:

```json
{
  "jacs_agent_private_key_filename": "private.pem"
}
```

Use the filename produced by agent creation; do not rename encrypted key files independently of their config.

#### jacs_agent_public_key_filename

Name of the public key file:

```json
{
  "jacs_agent_public_key_filename": "public.pem"
}
```

#### jacs_private_key_password

Supply the password through the host's `JACS_PRIVATE_KEY_PASSWORD`, a protected password file or the OS keychain. Do not persist plaintext passwords in JSON config. See [password sources](../reference/configuration.md#os-keychain-configuration).

### Storage Configuration

#### jacs_default_storage

Specifies where documents are stored:

| Value | Description |
|-------|-------------|
| `fs` | Local filesystem |
| `memory` | In-memory storage |
| `aws` | AWS S3; requires a build with the `s3` feature |
| `rusqlite` | Indexed SQLite; requires the `sqlite` feature |
| `sqlite` | SQLx SQLite storage; requires the `sqlx-sqlite` feature |

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

DNS compares a published fingerprint with the selected native key; strict mode also validates DNSSEC. A domain does not independently authorize an agent.

#### jacs_agent_domain

The domain used for DNS fingerprint checks. Configure it during agent creation, then publish the [required TXT record](../rust/dns.md).

#### jacs_dns_validate

Controls whether native verification attempts DNS, with the domain and explicit CLI options determining the effective behavior. See the [DNS mode table](../rust/dns.md).

#### jacs_dns_strict

This field exists in the schema, but the current native loader does not apply it to the runtime strict flag. Use `jacs-compat agent verify --require-strict-dns` or `AgentBuilder::dns_strict(true)` to require strict validation. A verified DNS claim also forces strict validation.

#### jacs_dns_required

Controls whether a domain and successful DNS validation are required. Select CLI flags or builder settings explicitly when this is part of the application's policy.

### Security

#### jacs_keychain_backend

OS keychain backend for password storage. Controls whether JACS looks up the private key password from the OS credential store.

```json
{
  "jacs_keychain_backend": "auto"
}
```

| Value | Description |
|-------|-------------|
| `"auto"` | Detect platform default (macOS Keychain or Linux Secret Service) |
| `"macos-keychain"` | macOS Keychain |
| `"linux-secret-service"` | Linux D-Bus Secret Service |
| `"disabled"` | Never consult OS keychain (recommended for CI/headless) |

Override with env var: `JACS_KEYCHAIN_BACKEND=disabled`

See [OS Keychain Configuration](../reference/configuration.md#os-keychain-configuration) for full details.

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
| `JACS_PRIVATE_KEY_PASSWORD` | Host password source; do not write it into config |
| `JACS_DATA_DIRECTORY` | `jacs_data_directory` |
| `JACS_KEY_DIRECTORY` | `jacs_key_directory` |
| `JACS_KEYCHAIN_BACKEND` | `jacs_keychain_backend` |

## See Also

- [Configuration Reference](../reference/configuration.md) - Full configuration guide with examples
- [JSON Schemas Overview](overview.md) - Schema architecture
- [Observability (Rust API)](../rust/observability.md) - Rust observability API
- [Observability & Monitoring Guide](../guides/observability.md) - Structured events, OTEL collector setup
