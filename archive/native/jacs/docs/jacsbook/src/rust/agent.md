# Creating an Agent

An agent is the fundamental identity in JACS: an entity with signing keys that can create, sign, and verify documents.

## What is an Agent?

A JACS agent is:

- A stable UUID identity
- A holder of cryptographic signing keys
- A self-signed identity document
- An optional DNS-verifiable identity

Capabilities for A2A interoperability live in A2A Agent Cards. The JACS agent document stays focused on identity and signing metadata.

## Creating Your First Agent

```bash
jacs init
```

This creates:

- Configuration file
- Cryptographic key pair
- Initial agent document

## Manual Creation

```bash
jacs config create
jacs agent create --create-keys true
```

## Custom Agent Definition

Create an agent definition file:

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "myagent.example.com",
  "name": "Content Creation Agent",
  "description": "AI agent specialized in content creation"
}
```

Then create the agent:

```bash
jacs agent create --create-keys true -f my-agent.json
```

## Agent Types

| Type | Description |
|------|-------------|
| `ai` | Fully artificial intelligence |
| `human` | Individual person |
| `human-org` | Organization or group |
| `hybrid` | Human-AI combination |

## Cryptographic Keys

New agents hold two key roles:

| Role | Algorithm | Purpose |
|------|-----------|---------|
| `native_root` | `pq2025` (default) or `ring-Ed25519` | Signs native JACS documents. Creation honors explicit Ed25519 selection. Rotation preserves the current algorithm unless Ed25519 explicitly upgrades to `pq2025`; downgrade is rejected. |
| `ecosystem_signing` | `ES256` (ECDSA P-256) | Compatibility credential for ecosystems that require classical signatures (JWKS/DID/A2A). Never signs native documents. |

Use `ed25519` as the user-facing creation label; configuration and signed
documents use the canonical `ring-Ed25519` wire label.

The compatibility key is minted eagerly at creation (skip with
`CreateAgentParams::builder().no_compat_key(true)` or the CLI
`--no-compat-key`). Existing agents migrate explicitly:

```rust,ignore
let compat = agent.add_compat_key()?; // role, algorithm, RFC 7638 kid, paths
let info = agent.ecosystem_key_info()?; // typed KeyNotFound when absent
```

Roles are recorded in `jacs_keys/jacs.keyring.json` (metadata only); the
ES256 private key uses the same AES-256-GCM + Argon2id envelope and 0600
permissions as the native root.

## Verifying Agents

```bash
jacs agent verify
jacs agent verify -a ./path/to/agent.json
jacs agent verify --require-dns
jacs agent verify --require-strict-dns
```

## HTTP protocol helpers

`SimpleAgent` signs request context and complete response envelopes without
exposing its internal mutex:

```rust
use std::collections::HashMap;
use jacs::{protocol::verify_signed_event_with_trusted_keys, simple::SimpleAgent};

let (agent, _) = SimpleAgent::ephemeral(Some("ed25519"))?;
let body = br#"{"action":"approve"}"#;
let authorization = agent.build_request_auth_header(
    "POST",
    "https://api.example.com/v1/jobs?mode=strict",
    body,
    "jobs-api",
)?;

let envelope = agent.sign_response(&serde_json::json!({"decision": "allow"}))?;
let signer_id = envelope["jacsSignature"]["agentID"]
    .as_str()
    .ok_or("missing signer ID")?;
let keys = HashMap::from([(signer_id.to_owned(), agent.get_public_key()?)]);
let verified = verify_signed_event_with_trusted_keys(&envelope, &keys)?;
assert!(authorization.starts_with("JACS v2."));
assert_eq!(verified.data["decision"], "allow");
```

The request header binds method, absolute URL including query, exact body
bytes, audience, key, time, and nonce. The response signature covers both data
and every envelope field. The verifier rejects unsigned/plain events, unknown
signers, legacy payload-only envelopes, and any metadata or payload mutation.
See [Security](../advanced/security.md#request-bound-http-authorization) for
server replay-store requirements and migration from unbound headers.

The supplied key map is the trust boundary. A valid signature proves possession
of that key, not a real-world identity unless the application established the
signer-to-key association under its configured policy.

## Agent Document Structure

```json
{
  "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "123e4567-e89b-12d3-a456-426614174000",
  "jacsVersionDate": "2024-01-15T10:30:00Z",
  "jacsOriginalVersion": "123e4567-e89b-12d3-a456-426614174000",
  "jacsOriginalDate": "2024-01-15T10:30:00Z",
  "jacsType": "agent",
  "jacsLevel": "config",
  "jacsAgentType": "ai",
  "jacsAgentDomain": "myagent.example.com",
  "name": "Content Creation Agent",
  "description": "AI agent for content generation",
  "jacsSha256": "hash-of-document",
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "123e4567-e89b-12d3-a456-426614174000",
    "signature": "base64-encoded-signature",
    "signingAlgorithm": "ring-Ed25519",
    "publicKeyHash": "hash-of-public-key",
    "date": "2024-01-15T10:30:00Z",
    "fields": ["jacsId", "jacsVersion", "jacsAgentType", "jacsAgentDomain", "name"]
  }
}
```

## Best Practices

1. Protect private keys.
2. Prefer strong signing algorithms.
3. Enable DNS verification for production agents.
4. Keep A2A capabilities in the A2A Agent Card.
5. Track agent document versions.

## Next Steps

- [Working with Documents](documents.md)
- [Agreements](agreements.md)
- [DNS Verification](dns.md)
