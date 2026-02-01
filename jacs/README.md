# JACS: JSON Agent Communication Standard

Cryptographic signing and verification for AI agents.

```bash
cargo install jacs
```

## Quick Start

```rust
use jacs::simple::{load, sign_message, verify};

// Load agent
load(None)?;

// Sign a message
let signed = sign_message(&serde_json::json!({"action": "approve"}))?;

// Verify it
let result = verify(&signed.raw)?;
assert!(result.valid);
```

## 6 Core Operations

| Operation | Description |
|-----------|-------------|
| `create()` | Create a new agent with keys |
| `load()` | Load agent from config |
| `verify_self()` | Verify agent integrity |
| `sign_message()` | Sign JSON data |
| `sign_file()` | Sign files with embedding |
| `verify()` | Verify any signed document |

## Features

- RSA, Ed25519, and post-quantum (ML-DSA) cryptography
- JSON Schema validation
- Multi-agent agreements
- MCP and A2A protocol support
- Python, Go, and NPM bindings

## CLI

```bash
jacs create              # Create new agent
jacs sign-message "hi"   # Sign a message
jacs sign-file doc.pdf   # Sign a file
jacs verify doc.json     # Verify a document
```

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Rust API](https://docs.rs/jacs/latest/jacs/)
- [Python](https://pypi.org/project/jacs/)
- [Crates.io](https://crates.io/crates/jacs)

**Version**: 0.4.0 | [HAI.AI](https://hai.ai)
