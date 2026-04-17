# JACS: JSON Agent Communication Standard

Cryptographic identity, signing, and verification for AI agents.

**[Documentation](https://humanassisted.github.io/JACS/)** | **[Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)** | **[API Reference](https://docs.rs/jacs/latest/jacs/)**

```bash
cargo install jacs-cli
```

## What it does

| Capability | Description |
|-----------|-------------|
| **Agent Identity** | Generate a cryptographic keypair. Post-quantum (ML-DSA-87) or Ed25519 for new agents; RSA-PSS remains verification-only for legacy artifacts. |
| **Data Provenance** | Sign any JSON document or file with tamper-evident signatures. |
| **Agent Trust** | Verify identities, manage trust stores, enforce trust policies across agents. |

## Quick start (Rust)

```rust
use jacs::simple::{load, sign_message, verify};

load(None)?;

let signed = sign_message(&serde_json::json!({"action": "approve"}))?;

let result = verify(&signed.raw)?;
assert!(result.valid);
```

## CLI

```bash
jacs quickstart --name my-agent --domain example.com
jacs document create -f mydata.json
jacs verify signed-document.json
jacs mcp                # start MCP server (stdio only)
```

## Security

- Password entropy validation for key encryption
- Private key zeroization on drop
- Algorithm identification embedded in signatures with downgrade prevention
- DNSSEC-validated identity verification
- MCP server uses stdio only — no network exposure
- 260+ automated tests covering cryptographic operations and attack scenarios

Report vulnerabilities to security@hai.ai.

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Rust API](https://docs.rs/jacs/latest/jacs/)
- [Crates.io](https://crates.io/crates/jacs)
- [Development Guide](../DEVELOPMENT.md)

**Version**: 0.9.7 | [HAI.AI](https://hai.ai)
