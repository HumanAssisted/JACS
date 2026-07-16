# JACS Rust Crate

Cryptographic identity, signing, and verification for agent systems.

This crate is the source implementation for portable JACS signatures: it canonicalizes and signs JSON documents, verifies schema-backed envelopes, and exposes the primitives that Python, Node.js, Go, CLI, and MCP integrations build on.

**[Documentation](https://humanassisted.github.io/JACS/)** | **[Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)** | **[API Reference](https://docs.rs/jacs/latest/jacs/)**

```bash
cargo add jacs serde_json
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
| ES256 compatibility key and ecosystem exports (JWKS, key binding, A2A agent card, AP2 mandate, agreement VC) | `jacs::compatibility` |
| Standalone Agreement v2, storage, DNS, and trust | Core crate modules |

## Quick start

```rust
use jacs::simple::SimpleAgent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (agent, info) = SimpleAgent::ephemeral(None)?;
    let signed = agent.sign_message(&serde_json::json!({"action": "approve"}))?;
    let result = agent.verify(&signed.raw)?;

    assert!(result.valid);
    println!(
        "verified {} signed by {}",
        signed.document_id, info.agent_id
    );
    Ok(())
}
```

## Request authentication and signed events

Use the exact bytes and target that will cross the HTTP boundary. The
credential binds the normalized method, absolute URL including query, SHA-256
digest of the exact body bytes, audience, signer/key, issue time, and nonce:

```rust
use jacs::simple::SimpleAgent;

let (agent, _) = SimpleAgent::ephemeral(Some("ed25519"))?;
let body = br#"{"action":"approve"}"#;
let authorization = agent.build_request_auth_header(
    "POST",
    "https://api.example.com/v1/jobs?mode=strict",
    body,
    "jobs-api",
)?;
assert!(authorization.starts_with("JACS v2."));
```

On the server, pass the same request context and an explicitly trusted public
key to `jacs::protocol::verify_request_auth_header`. It validates the request,
key binding, freshness, signature, and atomically consumes the nonce. A
multi-replica service must install a shared atomic `ReplayStore`. If the
application already has a shared nonce store, use
`verify_request_auth_header_with_trusted_key_without_replay` and grant access
only after that store atomically accepts the returned nonce.

Responses use the fully bound v2 envelope and pinned server keys:

```rust
use std::collections::HashMap;
use jacs::protocol::verify_signed_event_with_trusted_keys;

let envelope = agent.sign_response(&serde_json::json!({"decision": "allow"}))?;
let signer_id = envelope["jacsSignature"]["agentID"]
    .as_str()
    .ok_or("missing signer ID")?;
let keys = HashMap::from([(signer_id.to_owned(), agent.get_public_key()?)]);
let verified = verify_signed_event_with_trusted_keys(&envelope, &keys)?;
assert_eq!(verified.data["decision"], "allow");
```

The `jacs-response-v2` signature covers the payload, version/type, issuer,
document ID, hash, timestamp, signer, algorithm, key hash, and additional
fields. Plain events, unknown signers, legacy payload-only envelopes, and any
mutation are errors. Verification proves control of the key pinned for that
signer ID; real-world identity still depends on the caller's trust policy.

The no-argument `protocol::build_auth_header` remains available for source
compatibility and logs every use at WARN. Strict deployments can reject it with
`JACS_REJECT_UNBOUND_AUTH_HEADER=true`.

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
jacs document create -f mydata.json --output signed-document.json
jacs verify jacs_data/signed-document.json
jacs agreement-v2 verify --agreement agreement.json
jacs mcp                # start MCP server (stdio only)
```

Agreement v2 is the preferred model for new multi-agent consent workflows. It creates standalone `jacsType: "agreement"` documents with terms, parties, transcript references, signer/witness/notary policy, branch handling, and portable verification. The older `jacsAgreement` sidecar remains for simple countersignature metadata on existing documents.

## Security

- Password entropy validation for key encryption
- Private key zeroization on drop
- Algorithm identification embedded in signatures with downgrade prevention
- DNSSEC-aware identity verification paths
- Stdio-only MCP server; no network listener
- `pq2025` / ML-DSA-87 is the default native algorithm; explicit `ed25519` creation is supported. The ES256 compatibility key is bound to the selected native root and never signs native documents

Report vulnerabilities to security@hai.ai.

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Rust API](https://docs.rs/jacs/latest/jacs/)
- [Crates.io](https://crates.io/crates/jacs)
- [Development Guide](../DEVELOPMENT.md)

**Version**: 0.11.4 | [Apache-2.0](../LICENSE-APACHE)
