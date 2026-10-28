# Rust and CLI installation

## Portable CLI and MCP

```bash
cargo install jacs-cli --locked
jacs mcp
```

The `jacs` binary starts MCP in verification-only mode by default. For signing,
create an encrypted identity and explicitly select it; see the
[quick start](../getting-started/quick-start.md) and
[current MCP guide](https://humanassisted.github.io/JACS/mcp-quickstart.html).

## Native integrations

The extended commands documented in this reference use a separate executable:

```bash
cargo install jacs-cli-compat --locked
jacs-compat quickstart --name my-agent --domain my-agent.example.com
jacs-compat --help
```

Its `jacs.config.json`, key directories, DNS, storage and extended MCP profiles
belong to the native compatibility workspace. See [CLI usage](cli.md).

## Rust libraries

For portable cryptography without I/O:

```toml
[dependencies]
jacs-core = "=0.15.0"
serde_json = "1"
```

For native identity, storage and integrations:

```toml
[dependencies]
jacs = "=0.15.0"
serde_json = "1"
```

Native optional features include `a2a`, `agreements`, `attestation`, `s3`,
`sqlx-sqlite`, `otlp-logs`, `otlp-metrics` and `otlp-tracing`; SQLite is enabled
by default. Select only the features your integration needs. The
[library guide](library.md) covers the native API.

## Publication and platforms

The [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
records 0.15.0 across all 17 Rust crates, CLI archives and language packages.
Cargo builds libraries from source. CLI archives cover macOS arm64/x86_64,
Linux glibc arm64/x86_64 and Windows x86_64; this does not imply Windows Python,
Node or Go native artifacts. See [deployment compatibility](../getting-started/deployment.md).

The browser package is published as `@hai.ai/jacs-wasm`; see its
[installation guide](../wasm/building.md). New identity standards behavior in
this checkout is source work, not a claim about already published 0.15.0 artifacts.

## Build this checkout

Source builds require Rust 1.97 or newer (Edition 2024), a linker and any native
system dependencies. From the repository root:

```bash
git clone https://github.com/HumanAssisted/JACS.git
cd JACS
cargo install --path jacs-cli --locked
cargo install --path archive/native/jacs-cli --locked
```

The active workspace contains `jacs-core`, `jacs-wasm`, `jacs-mobile`, `jacs-mcp`
and `jacs-cli`. Native packages use `archive/native/Cargo.toml`; for example:

```bash
cargo check --manifest-path archive/native/Cargo.toml -p jacs --locked
```

Use the [developer commands](https://humanassisted.github.io/JACS/development.html)
for binding builds and the shared Rust cache setup before substantial builds.
Never place a key password in command arguments. Use the prompt or host secret
source documented for the selected CLI.
