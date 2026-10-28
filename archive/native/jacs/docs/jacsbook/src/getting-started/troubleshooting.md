# Troubleshooting

Common issues and solutions when installing or using JACS.

## Installation Issues

### pip install fails

Published 0.15.0 wheels support Python 3.10–3.14; this source checkout requires
Python 3.11–3.14. If no pre-built wheel exists for your platform, install the Rust toolchain and build from source:

```bash
pip install maturin
make build-jacspy  # from the repository root
```

### npm install fails

Native npm binaries cover macOS x64/arm64 and Linux x64/arm64 for glibc and
musl. There is no Windows addon; a Windows CLI archive is a separate artifact.
For custom source builds, use `make build-jacsnpm` from the repository root
with the documented Node and Rust toolchains.

### Alpine Linux / musl libc

Published 0.15.0 includes a Python musllinux x86_64 wheel and npm musl
x86_64/arm64 addons. CLI archives are glibc-only; the Python/npm CLI shims
reject musl even when library APIs work. Match the artifact to architecture
and libc; see [deployment compatibility](deployment.md).

## Configuration Issues

### Config not found

Run `jacs-compat quickstart --name my-agent --domain my-agent.example.com` to auto-create a config, or copy the example:

```bash
cp jacs.config.example.json jacs.config.json
```

### Private key decryption failed

Wrong or missing password. Check `JACS_PRIVATE_KEY_PASSWORD`. For CLI, you may also set `JACS_PASSWORD_FILE` to a file that contains only the password, or use `jacs-compat keychain set` to store the password in the OS keychain. Set exactly one explicit source; if both env var and password file are set, CLI fails by design. The OS keychain is only consulted when neither env var nor password file is present.

### Algorithm detection failed

Set `jacs_agent_key_algorithm` in the config, or pass the algorithm explicitly
to `quickstart(...)` / `create(...)`. User-facing values are `pq2025` and
`ed25519`; the legacy input alias and canonical Ed25519 wire label are
`ring-Ed25519`.

## Runtime Issues

### Agent creation fails

Ensure the data and key directories exist and are writable. By default these are `./jacs_data` and `./jacs_keys`.

### Signature verification fails

Ensure the signer's public key is accessible. If verifying a document from another agent, you may need to import their public key or use the trust store.

### Documents not found

Check the `jacs_data_directory` path in your config. Documents are stored as JSON files in that directory.

## Building from Source

```bash
git clone https://github.com/HumanAssisted/JACS.git
cd JACS

# Rust core + CLI
cargo build --release
cargo install --path jacs-cli --locked

# Python binding
make build-jacspy  # from the repository root

# Node.js binding
make build-jacsnpm
```

Requires Rust 1.97+ (install via [rustup](https://rustup.rs/)).

## Getting Help

- [GitHub Issues](https://github.com/HumanAssisted/JACS/issues) -- report bugs and feature requests
- [Quick Start Guide](quick-start.md) -- step-by-step setup
