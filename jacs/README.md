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

## Security

**Security Hardening**: This library includes:
- Password entropy validation for key encryption (minimum 40 bits)
- Thread-safe environment variable handling
- TLS certificate validation enabled by default
- Private key zeroization on drop
- Algorithm identification embedded in signatures

**Reporting Vulnerabilities**: Please report security issues responsibly.
- Email: security@hai.ai
- Do **not** open public issues for security vulnerabilities
- We aim to respond within 48 hours

**Best Practices**:
- Use strong passwords (12+ characters with mixed case, numbers, symbols)
- Store private keys securely with appropriate file permissions
- Keep JACS and its dependencies updated

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Rust API](https://docs.rs/jacs/latest/jacs/)
- [Python](https://pypi.org/project/jacs/)
- [Crates.io](https://crates.io/crates/jacs)

**Version**: 0.4.0 | [HAI.AI](https://hai.ai)
