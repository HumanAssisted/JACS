# Installation

This guide covers installing the JACS Rust CLI and library.

## Requirements

- **Rust**: Version 1.93 or later (Edition 2024)
- **Cargo**: Included with Rust installation

### Verify Rust Version
```bash
rustc --version
# Should show rustc 1.93.0 or later
```

If you need to update Rust:
```bash
rustup update stable
```

## Installing the CLI

### From crates.io (Recommended)
```bash
cargo install jacs --features cli
```

### From Source
```bash
git clone https://github.com/HumanAssisted/JACS
cd JACS/jacs
cargo install --path . --features cli
```

### Verify Installation
```bash
jacs --help
```

## Using as a Library

Add JACS to your `Cargo.toml`:

```toml
[dependencies]
jacs = "0.3"
```

### With Optional Features

JACS supports several optional features for observability and integrations:

```toml
[dependencies]
# Basic library usage
jacs = "0.3"

# With OpenTelemetry logging
jacs = { version = "0.3", features = ["otlp-logs"] }

# With OpenTelemetry metrics
jacs = { version = "0.3", features = ["otlp-metrics"] }

# With OpenTelemetry tracing
jacs = { version = "0.3", features = ["otlp-tracing"] }

# With all observability features
jacs = { version = "0.3", features = ["otlp-logs", "otlp-metrics", "otlp-tracing"] }
```

### Available Features

| Feature | Description |
|---------|-------------|
| `cli` | Enables CLI binary build with clap and ratatui |
| `otlp-logs` | OpenTelemetry Protocol logging backend |
| `otlp-metrics` | OpenTelemetry Protocol metrics backend |
| `otlp-tracing` | OpenTelemetry Protocol distributed tracing |
| `observability-convenience` | Helper wrappers for metrics and logging |
| `mcp-server` | Model Context Protocol server integration surface |

## Platform Support

JACS supports the following platforms:

| Platform | Architecture | Support |
|----------|-------------|---------|
| Linux | x86_64, aarch64 | Full support |
| macOS | x86_64, aarch64 | Full support |
| Windows | x86_64 | Full support |
| WebAssembly | wasm32 | Partial (no post-quantum crypto, limited storage) |

### WebAssembly Notes

When targeting WebAssembly, some features are unavailable:
- Post-quantum cryptographic algorithms (pq-dilithium)
- File system storage backend
- HTTP-based remote operations

## Configuration

After installation, initialize JACS:

```bash
# Create configuration and agent in one step
jacs init
```

This creates:
- `~/.jacs/jacs.config.json` - Configuration file
- Cryptographic keys for your agent
- Initial agent document

### Manual Configuration

Alternatively, create configuration and agent separately:

```bash
# Create configuration only
jacs config create

# Create agent with keys
jacs agent create --create-keys true
```

### Environment Variables

JACS respects the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `JACS_CONFIG_PATH` | Path to configuration file | `./jacs.config.json` |
| `JACS_USE_SECURITY` | Enable/disable security features | `true` |
| `JACS_DATA_DIRECTORY` | Directory for document storage | `./jacs_data` |
| `JACS_KEY_DIRECTORY` | Directory for cryptographic keys | `./jacs_keys` |
| `JACS_DEFAULT_STORAGE` | Storage backend (`fs`, `memory`) | `fs` |
| `JACS_AGENT_KEY_ALGORITHM` | Key algorithm (`ring-Ed25519`, `RSA-PSS`, `pq-dilithium`) | `ring-Ed25519` |

## Troubleshooting

### Build Errors

**"edition 2024 is required"**
Update Rust to version 1.93 or later:
```bash
rustup update stable
```

**Missing dependencies on Linux**
Install build essentials:
```bash
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config libssl-dev

# Fedora
sudo dnf install gcc openssl-devel
```

### Runtime Errors

**"Configuration file not found"**
Run `jacs init` or set `JACS_CONFIG_PATH` environment variable.

**"Key directory does not exist"**
Create the key directory or run `jacs init`:
```bash
mkdir -p ./jacs_keys
```

**"Permission denied"**
Ensure you have write permissions to the data and key directories.

## Next Steps

- [CLI Usage](cli.md) - Learn CLI commands
- [Creating an Agent](agent.md) - Create your first agent
- [Rust Library API](library.md) - Use JACS as a library
