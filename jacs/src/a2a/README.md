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
  export_agent_card()
      |
A2A Agent Card (v0.4.0)
      |
  sign_agent_card_jws() + embed_signature_in_agent_card()
      |
Signed Agent Card (signatures embedded)
      |
/.well-known/agent-card.json (discoverable)
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

### 3. Dual Key Management (`keys.rs`)
Generates and manages two key pairs:
- **JACS Key**: Post-quantum (Dilithium/Falcon/SPHINCS+) for documents
- **A2A Key**: RSA (and Ed25519 via `ring-Ed25519`) for JWS Agent Card signing

### 4. Extension Management (`extension.rs`)
- Signs Agent Cards with JWS
- Embeds signatures in `AgentCard.signatures` (v0.4.0)
- Generates .well-known endpoints
- Creates JACS descriptor documents

### 5. Provenance Wrapping (`provenance.rs`)
- Wraps A2A artifacts with JACS signatures (generic `Value` or typed `A2AArtifact`/`A2AMessage`)
- Verifies wrapped artifacts, including foreign agents when keys are resolvable via configured key sources
- Creates chain of custody documents

## Usage

### Rust

```rust
use jacs::a2a::{agent_card::*, keys::*, extension::*, provenance::*};

// Export JACS agent to A2A Agent Card (v0.4.0)
let agent_card = export_agent_card(&agent)?;

// Generate dual keys
let dual_keys = create_jwk_keys(Some("dilithium"), Some("rsa"))?;

// Sign Agent Card with JWS
let jws_signature = sign_agent_card_jws(
    &agent_card,
    &dual_keys.a2a_private_key,
    &dual_keys.a2a_algorithm,
    &agent_id,
)?;

// Embed signature in Agent Card (v0.4.0)
let signed_card = embed_signature_in_agent_card(&agent_card, &jws_signature, None);

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
- `/.well-known/jwks.json` — JWK Set for verification
- `/.well-known/jacs-agent.json` — JACS agent descriptor
- `/.well-known/jacs-pubkey.json` — JACS public key

## JACS Extension for A2A

The JACS extension declaration in Agent Cards (v0.4.0):

```json
{
  "capabilities": {
    "extensions": [{
      "uri": "urn:hai.ai:jacs-provenance-v1",
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

1. **Key Separation**: JACS and A2A keys are separate
2. **Algorithm Choice**: Use PQC for long-term security
3. **Verification**: Always verify wrapped artifacts
4. **Chain of Custody**: Maintain for compliance
5. **Signature Embedding**: v0.4.0 embeds signatures in the AgentCard rather than external wrappers
