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
- Signed agent state (memory, skills, plans, configs, hooks, or any document)
- Commitments (shared signed agreements between agents)
- Todo lists (private signed task tracking with cross-references)
- Conversation threading (ordered, signed message chains)
- PostgreSQL database storage (optional, `database` feature flag)
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
- Password entropy validation for key encryption (minimum 28 bits, 35 bits for single character class)
- Thread-safe environment variable handling
- TLS certificate validation (warns by default; set `JACS_STRICT_TLS=true` for production)
- Private key zeroization on drop
- Algorithm identification embedded in signatures
- Verification claim enforcement with downgrade prevention
- DNSSEC-validated identity verification for verified agents

**Test Coverage**: JACS includes 260+ automated tests covering cryptographic operations (RSA, Ed25519, post-quantum ML-DSA), password validation, agent lifecycle, DNS identity verification, trust store operations, and claim-based security enforcement. Security-critical paths are tested with boundary conditions, failure cases, and attack scenarios (replay attacks, downgrade attempts, key mismatches).

**Reporting Vulnerabilities**: Please report security issues responsibly.
- Email: security@hai.ai
- Do **not** open public issues for security vulnerabilities
- We aim to respond within 48 hours

**Dependency audit**: To check Rust dependencies for known vulnerabilities, run: `cargo install cargo-audit && cargo audit`.

**Best Practices**:
- Do not put the private key password in config; set `JACS_PRIVATE_KEY_PASSWORD` only.
- Use strong passwords (12+ characters with mixed case, numbers, symbols)
- Store private keys securely with appropriate file permissions
- Keep JACS and its dependencies updated

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Rust API](https://docs.rs/jacs/latest/jacs/)
- [Python](https://pypi.org/project/jacs/)
- [Crates.io](https://crates.io/crates/jacs)

**Version**: 0.5.1 | [HAI.AI](https://hai.ai)
