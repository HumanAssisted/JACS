# Installation

This guide covers installing the JACS Rust CLI and library.

## Requirements

- **Rust**: Version 1.97 or later (Edition 2024)
- **Cargo**: Included with Rust installation

### Verify Rust Version
```bash
rustc --version
# Should show rustc 1.97.0 or later
```

If you need to update Rust:
```bash
rustup update stable
```

## Installing the CLI

### From crates.io (Recommended)
```bash
cargo install jacs-cli
```

At the 2026-07-09 shipped-artifact snapshot, crates.io resolves `jacs-cli`
`0.11.3`; the documentation source is `0.11.4`. Check the resolved version
instead of assuming the source branch has already been published.

### From Homebrew (macOS)
```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

### From Source
```bash
git clone https://github.com/HumanAssisted/JACS
cd JACS
cargo install --path jacs-cli
```

### Verify Installation
```bash
jacs --help
```

### MCP Server

The MCP server is built into the `jacs` binary. No separate install step needed.

```bash
# Start the MCP server (stdio transport)
JACS_CONFIG="$PWD/jacs.config.json" jacs mcp
```

## Using as a Library

Add JACS to your `Cargo.toml`:

```toml
[dependencies]
jacs = "0.11.3"
```

`0.11.3` is the published crate recorded in
`release/shipped-artifacts.json`; source checkout `0.11.4` is not installable
from crates.io until its release completes.

### With Optional Features

JACS supports several optional features for observability and integrations:

```toml
[dependencies]
# Basic library usage
jacs = "0.11.3"

# With OpenTelemetry logging
jacs = { version = "0.11.3", features = ["otlp-logs"] }

# With OpenTelemetry metrics
jacs = { version = "0.11.3", features = ["otlp-metrics"] }

# With OpenTelemetry tracing
jacs = { version = "0.11.3", features = ["otlp-tracing"] }

# With all observability features
jacs = { version = "0.11.3", features = ["otlp-logs", "otlp-metrics", "otlp-tracing"] }
```

### Available Features

| Feature | Description |
|---------|-------------|
| `cli` | _(Deprecated -- use `cargo install jacs-cli` instead)_ |
| `otlp-logs` | OpenTelemetry Protocol logging backend |
| `otlp-metrics` | OpenTelemetry Protocol metrics backend |
| `otlp-tracing` | OpenTelemetry Protocol distributed tracing |
| `sqlite` | Lightweight sync SQLite backend (default) |
| `sqlx-sqlite` | Async SQLite backend via sqlx (requires tokio) |
| `s3` | AWS S3 storage; opt-in because it adds cloud HTTP/XML dependencies |
| `agreements` | Agreement lifecycle support |
| `a2a` | Agent-to-Agent protocol support |
| `attestation` | Attestation support |

## Platform Support

The Rust crate and the CLI have different distribution models. The `jacs`
crate is source compiled by Cargo; a successful build depends on the Rust
target, linker, and system dependencies available to the consumer. The CLI is
also published as platform archives.

Observed public artifacts on 2026-07-09:

| Surface | Version | Prebuilt targets | Test evidence |
|---|---|---|---|
| Rust library crate | `jacs 0.11.3` | None; crates.io distributes source | Full source suites run in release CI on Ubuntu and macOS. This does not imply every Rust-supported target. |
| CLI crate | `jacs-cli 0.11.3` | `cargo install` builds from source | Source compilation follows the consumer's Rust target and native dependencies. |
| CLI archives | `jacs-cli 0.11.3` | macOS arm64/x86_64; glibc Linux arm64/x86_64; Windows x86_64 | The release job builds each target and executes `jacs --version` on its runner. Full feature suites are not run separately on every archive target. |
| Browser WASM | source `0.11.4` only | No published `@jacs/wasm` package | Source CI runs Firefox `wasm-pack` tests and a Chromium/Playwright package smoke on Ubuntu. |

There is no basis for a blanket “full support” claim across operating systems.
In particular, the Windows x86_64 CLI archive does not imply Windows wheels or
native modules for Python, Node, or Go. See
[Deployment Compatibility](../getting-started/deployment.md) for the exact
cross-language, architecture, and libc matrix.

### WebAssembly Notes

The source-built `jacs-wasm` package supports both Ed25519 and post-quantum
`pq2025` signing and verification. The previous claim that WebAssembly lacked
post-quantum support was incorrect.

The WASM surface remains browser-specific and omits native filesystem storage,
DNS resolution, MCP, and the CLI. It uses encrypted browser persistence, and
its private keys live in JavaScript-visible WebAssembly memory. Most
importantly for installation, `@jacs/wasm` was not published to npm at the
shipped-artifact observation date; build it from source rather than running the
unqualified npm install command until a registry version exists.

## Configuration

After installation, initialize JACS:

```bash
# Create configuration and agent in one step
jacs init
```

This creates:
- `./jacs.config.json` - Configuration file
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
| `JACS_AGENT_KEY_ALGORITHM` | Key algorithm (`ed25519`, `pq2025`; legacy alias `ring-Ed25519`) | `pq2025` |
| `JACS_ALLOW_LEGACY_SIGNATURE_CONTENT` | Explicitly allow payload-only verification of legacy v1 signatures; signer/version/time metadata stays untrusted and empty | `false` |
| `JACS_REJECT_LEGACY_SIGNATURE_CONTENT` | Force legacy-v1 rejection even if compatibility was requested | `false` |
| `JACS_PAYLOAD_MAX_REPLAY_SECONDS` | Freshness/nonce retention window for HTTP/RPC payload proofs | `300` |
| `JACS_REQUIRE_SHARED_REPLAY_STORE` | Fail closed unless an application-installed `ReplayStore` is shared across replicas | `false` |

## Troubleshooting

### Build Errors

**"edition 2024 is required"**
Update Rust to version 1.97 or later:
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
