# JACS A2A (Agent-to-Agent) Protocol Integration

This module provides integration between JACS (JSON Agent Communication Standard) and the A2A (Agent-to-Agent) protocol, positioning JACS as a cryptographic provenance extension to A2A.

**Implements A2A protocol v0.4.0 (September 2025).**

## Overview

JACS A2A integration enables:
- Export JACS agents as A2A Agent Cards (v0.4.0 schema)
- Sign Agent Cards with JWS embedded in the `signatures` field
- Wrap A2A artifacts with JACS cryptographic signatures
- Maintain chain of custody for multi-agent workflows
- Support for post-quantum cryptography

## Architecture

```
JACS Agent (PQC)
      |
  persisted ES256 compatibility key
      |
A2A Agent Card (v0.4.0)
      |
  JCS + ES256 JWS + native-root-signed binding
      |
Signed Agent Card (signatures embedded)
      |
/.well-known/{agent-card,jwks,jacs-compat-binding}.json
      |
A2A Artifacts <-- wrap_artifact_with_provenance()
      |
JACS-wrapped Artifact (signed + hash)
      |
verify_wrapped_artifact() --> VerificationResult
```

## Key Components

### 1. Core Types (`mod.rs`)
A2A v0.4.0 type definitions:
- `AgentCard` — with `protocolVersions`, `supportedInterfaces`, `defaultInputModes`/`defaultOutputModes`, `securitySchemes` (HashMap), `signatures`
- `AgentSkill` — with `id`, `name`, `description`, `tags` (no endpoints/schemas)
- `SecurityScheme` — tagged enum: `ApiKey`, `Http`, `OAuth2`, `OpenIdConnect`, `MutualTls`
- `AgentCapabilities` — `streaming`, `pushNotifications`, `extendedAgentCard`, `extensions`
- `AgentExtension` — `uri`, optional `description`, optional `required`
- `AgentInterface` — `url`, `protocolBinding`, optional `tenant`
- `TaskState`, `Role`, `Part`, `A2AArtifact`, `A2AMessage`, `A2ATask` — full A2A data model

### 2. Agent Card Export (`agent_card.rs`)
Converts JACS agents to A2A Agent Card format:
- Maps JACS services to A2A skills (with `id` and `tags`)
- Includes JACS extension declaration
- Builds `supportedInterfaces` from agent domain
- Security schemes as a keyed map

### 3. Identity Key Management (`keys.rs`, `compatibility/`)
- **Native JACS root**: `pq2025` or `ring-Ed25519` for native documents and the compatibility binding
- **A2A compatibility key**: persisted ES256 key for JCS/JOSE Agent Card signing
- The native-root-signed `a2a-agent-card` binding scope authorizes that exact ES256 JWK and `kid`
- Legacy caller-generated ephemeral discovery keys are rejected

### 4. Extension Management (`extension.rs`)
- Signs Agent Cards with the persisted ES256 compatibility key
- Embeds signatures in `AgentCard.signatures` (v0.4.0)
- Generates six stable .well-known endpoints, including the compatibility binding
- Creates JACS descriptor documents

### 5. Provenance Wrapping (`provenance.rs`)
- Wraps A2A artifacts with JACS signatures (generic `Value` or typed `A2AArtifact`/`A2AMessage`)
- Verifies wrapped artifacts, including foreign agents when keys are resolvable via configured key sources
- Creates chain of custody documents

## Usage

### Rust

```rust
use jacs::a2a::simple::generate_well_known_documents;

// Omit the compatibility-only algorithm argument. Discovery always reuses
// the persisted ES256 compatibility key and publishes its native binding.
let documents = generate_well_known_documents(&simple_agent, None)?;

// Wrap A2A artifact with JACS provenance
let wrapped = wrap_artifact_with_provenance(
    &mut agent,
    artifact,
    "task",
    None,
)?;
```

### Python

```python
from jacs.a2a import JACSA2AIntegration

# Initialize integration
a2a = JACSA2AIntegration("jacs.config.json")

# Export to Agent Card (v0.4.0)
agent_card = a2a.export_agent_card(agent_data)

# Wrap artifact with provenance
wrapped = a2a.wrap_artifact_with_provenance(artifact, "task")

# Verify wrapped artifact
result = a2a.verify_wrapped_artifact(wrapped)
```

## Well-Known Endpoints

JACS A2A integration provides these standard endpoints:

- `/.well-known/agent-card.json` — A2A Agent Card with embedded JWS signatures
- `/.well-known/jwks.json` — stable ES256 compatibility JWK
- `/.well-known/jacs-compat-binding.json` — native-root-signed ES256 identity binding
- `/.well-known/jacs-agent.json` — JACS agent descriptor
- `/.well-known/jacs-pubkey.json` — JACS public key
- `/.well-known/jacs-extension.json` — JACS provenance extension descriptor

## JACS Extension for A2A

The JACS extension declaration in Agent Cards (v0.4.0):

```json
{
  "capabilities": {
    "extensions": [{
      "uri": "urn:jacs:provenance-v1",
      "description": "JACS cryptographic document signing and verification",
      "required": false
    }]
  }
}
```

## Examples

See the `examples/` directory for:
- `a2a_simple_example.rs` — Basic integration demo
- `a2a_agent_example.rs` — Full agent with A2A support
- `a2a_complete_example.rs` — Complete workflow example

## Testing

Run integration tests:
```bash
cargo test --test a2a_integration_test
```

## Security Considerations

1. **Key Separation**: the native root authorizes, but does not replace, the persisted ES256 compatibility key
2. **Strict identity**: validate the fixed-path compatibility binding against an explicitly trusted native root; a self-advertised JWKS key alone is not identity proof
3. **Verified/TOFU**: proves same-origin key continuity only and remains distinguishable from explicit trust

Strict also enforces an absolute seven-day window from the binding's signed
`issuedAt` (plus five minutes of future clock skew), including on first
contact. Well-known generation refreshes an authentic binding after six days
under the shared issuance lock while preserving scopes and explicit expiry.
4. **Network boundary**: JWKS and binding fetches enforce HTTPS (except explicit loopback opt-in), DNS/IP pinning, same-origin redirects, MIME checks, timeouts, and a 256 KiB limit
5. **Verification**: always verify wrapped artifacts separately from Agent Card admission
6. **Chain of Custody**: maintain for compliance
