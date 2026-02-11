# Troubleshooting

Common issues and solutions when installing or using JACS.

## Installation Issues

### pip install fails

Check your Python version (3.10+ required). If no pre-built wheel exists for your platform, install the Rust toolchain and build from source:

```bash
pip install maturin
cd jacspy && maturin develop --release
```

### npm install fails

Pre-built binaries are available for Linux/macOS/Windows x64 and ARM64 macOS. If no pre-built binary matches your platform, you need the Rust toolchain installed so the native addon can compile during `npm install`.

### Alpine Linux / musl libc

The default wheels and binaries target glibc. On Alpine or other musl-based systems, build from source with the Rust toolchain, or use a Debian-based container image instead.

## Configuration Issues

### Config not found

Run `jacs quickstart` to auto-create a config, or copy the example:

```bash
cp jacs.config.example.json jacs.config.json
```

### Private key decryption failed

Wrong password. Check the `JACS_PRIVATE_KEY_PASSWORD` environment variable. If you used `quickstart()`, the auto-generated password is saved to `./jacs_keys/.jacs_password`.

### Algorithm detection failed

Set the `signingAlgorithm` field in your config, or pass it explicitly to `quickstart()` / `create()`. Valid values: `pq2025`, `ring-Ed25519`, `ring-RSA`.

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
cargo install --path jacs --features cli

# Python binding
cd jacspy && maturin develop --release

# Node.js binding
cd jacsnpm && npm run build
```

Requires Rust 1.93+ (install via [rustup](https://rustup.rs/)).

## Getting Help

- [GitHub Issues](https://github.com/HumanAssisted/JACS/issues) -- report bugs and feature requests
- [Quick Start Guide](quick-start.md) -- step-by-step setup
