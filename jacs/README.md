# JACS Rust Crate

Cryptographic identity, signing, and verification for agent systems.

This crate is the source implementation for portable JACS signatures: it canonicalizes and signs JSON documents, verifies schema-backed envelopes, and exposes the primitives that Python, Node.js, Go, CLI, and MCP integrations build on.

**[Documentation](https://humanassisted.github.io/JACS/)** | **[Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)** | **[API Reference](https://docs.rs/jacs/latest/jacs/)**

```bash
cargo add jacs
```

For the CLI and MCP server:

```bash
cargo install jacs-cli
```

## What it does

| Capability | Rust API |
|-----------|----------|
| Agent identity and schema-backed signed JSON | `jacs::simple` |
| Inline Markdown/text signatures | `jacs::text` |
| PNG/JPEG/WebP provenance | `jacs::media` |
| RFC 5322 email signatures | `jacs::email` |
| Agreements, storage, DNS, and trust | Core crate modules |

## Quick start

```rust
use jacs::simple::{load, sign_message, verify};

load(None)?;

let signed = sign_message(&serde_json::json!({"action": "approve"}))?;
let result = verify(&signed.raw)?;

assert!(result.valid);
```

## Artifact provenance

```rust
use jacs::media::{sign_image, verify_image, SignImageOptions};
use jacs::text::{sign_text_file, verify_text_file, VerifyOptions};

// Markdown/text: append an inline signature block.
sign_text_file(&agent, "README.md")?;
let text = verify_text_file(
    &agent,
    "README.md",
    VerifyOptions { strict: false, key_dir: None },
)?;

// Images: embed a JACS signature in PNG iTXt, JPEG APP11, or WebP XMP.
sign_image(&agent, "photo.png", "signed.png", SignImageOptions::default())?;
let image = verify_image(
    &agent,
    "signed.png",
    VerifyOptions { strict: false, key_dir: None },
)?;
```

Email signing is Rust-only today:

```rust
use jacs::email::{sign_email, verify_email};

let raw_eml = std::fs::read("outgoing.eml")?;
let signed_eml = sign_email(&raw_eml, &agent)?;

let sender_public_key = agent.get_public_key()?;
let result = verify_email(&signed_eml, &agent, &sender_public_key)?;
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
- DNSSEC-aware identity verification paths
- Stdio-only MCP server; no network listener
- `pq2025` / ML-DSA-87 is the default for new agents

Report vulnerabilities to security@hai.ai.

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Rust API](https://docs.rs/jacs/latest/jacs/)
- [Crates.io](https://crates.io/crates/jacs)
- [Development Guide](../DEVELOPMENT.md)

**Version**: 0.11.1 | [Apache-2.0](../LICENSE-APACHE)
