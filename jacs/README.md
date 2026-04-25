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

## What's new in 0.11.0

*Why this matters:* shared markdown reviewed by multiple agents and signed images for AI-era provenance now have first-class support — the signature lives inside the artifact, the file renders normally, and downstream consumers verify identity + claimed timestamp via the same JACS trust model they already use for JSON documents.

```rust
use jacs::media::{sign_image, verify_image, SignImageOptions};
use jacs::text::{sign_text_file, verify_text_file, VerifyOptions};

// Inline text — signature appended in a YAML-bodied block at end of file
sign_text_file(&agent, "README.md")?;
let report = verify_text_file(&agent, "README.md", VerifyOptions { strict: false, key_dir: None })?;
println!("status: {:?}", report.status);   // Signed { signers } | MissingSignature | Malformed

// Strict mode rejects missing signatures with ErrorKind::MissingSignature
let strict = verify_text_file(&agent, "README.md", VerifyOptions { strict: true, key_dir: None });

// Images — signature embedded in PNG iTXt / JPEG APP11 / WebP XMP
sign_image(&agent, "photo.png", "signed.png", SignImageOptions::default())?;
let result = verify_image(&agent, "signed.png", VerifyOptions { strict: false, key_dir: None })?;
```

A JACS inline signature proves "agent X signed these canonical bytes at their claimed time." It does not prove first creation or legal ownership.

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

**Version**: 0.11.0 | [HAI.AI](https://hai.ai)
