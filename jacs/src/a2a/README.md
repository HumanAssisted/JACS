# JACS A2A (Agent-to-Agent) Protocol Integration

This module provides integration between JACS (JSON Agent Communication Standard) and Google's A2A (Agent-to-Agent) protocol, positioning JACS as a cryptographic provenance extension to A2A.

## Overview

JACS A2A integration enables:
- Export JACS agents as A2A Agent Cards
- Sign Agent Cards with JWS for web compatibility
- Wrap A2A artifacts with JACS cryptographic signatures
- Maintain chain of custody for multi-agent workflows
- Support for post-quantum cryptography

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│   JACS Agent    │ ──────> │ A2A Agent Card  │
│                 │ export  │                 │
│ - PQC Signatures│         │ - JSON-RPC API  │
│ - Provenance    │         │ - Skills/Tools  │
│ - Verification  │         │ - Discovery     │
└─────────────────┘         └─────────────────┘
        │                           │
        │      ┌─────────────┐      │
        └──────│ JACS Ext.   │──────┘
               │ Declaration │
               └─────────────┘
```

## Key Components

### 1. Agent Card Export (`agent_card.rs`)
Converts JACS agents to A2A Agent Card format:
- Maps JACS services → A2A skills
- Includes JACS extension declaration
- Maintains agent metadata

### 2. Dual Key Management (`keys.rs`)
Generates and manages two key pairs:
- **JACS Key**: Post-quantum (Dilithium/Falcon/SPHINCS+) for documents
- **A2A Key**: RSA/ECDSA for JWS Agent Card signing

### 3. Extension Management (`extension.rs`)
- Signs Agent Cards with JWS
- Generates .well-known endpoints
- Creates JACS descriptor documents

### 4. Provenance Wrapping (`provenance.rs`)
- Wraps A2A artifacts with JACS signatures
- Verifies wrapped artifacts
- Creates chain of custody documents

## Usage

### Rust

```rust
use jacs::a2a::{agent_card::*, keys::*, extension::*, provenance::*};

// Export JACS agent to A2A Agent Card
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

# Export to Agent Card
agent_card = a2a.export_agent_card(agent_data)

# Wrap artifact with provenance
wrapped = a2a.wrap_artifact_with_provenance(
    artifact,
    "task"
)

# Verify wrapped artifact
result = a2a.verify_wrapped_artifact(wrapped)
```

## Well-Known Endpoints

JACS A2A integration provides these standard endpoints:

- `/.well-known/agent.json` - A2A Agent Card (JWS signed)
- `/.well-known/jwks.json` - JWK Set for verification
- `/.well-known/jacs-agent.json` - JACS agent descriptor
- `/.well-known/jacs-pubkey.json` - JACS public key

## JACS Extension for A2A

The JACS extension declaration in Agent Cards:

```json
{
  "capabilities": {
    "extensions": [{
      "uri": "urn:hai.ai:jacs-provenance-v1",
      "description": "JACS cryptographic document signing and verification",
      "required": false,
      "params": {
        "jacsDescriptorUrl": "https://agent.example.com/.well-known/jacs-agent.json",
        "signatureType": "JACS_PQC",
        "supportedAlgorithms": ["dilithium", "rsa", "ecdsa"],
        "verificationEndpoint": "/jacs/verify"
      }
    }]
  }
}
```

## Integration Benefits

### For JACS Users
- Participate in A2A agent networks
- Maintain cryptographic provenance
- Future-proof with post-quantum crypto

### For A2A Users
- Add document-level signatures
- Create verifiable audit trails
- Support compliance requirements

## Examples

See the `examples/` directory for:
- `a2a_simple_example.rs` - Basic integration demo
- `a2a_agent_example.rs` - Full agent with A2A support
- `a2a_complete_example.rs` - Complete workflow example

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

## Future Enhancements

- [ ] Full ECDSA support for JWK export
- [ ] Streaming artifact signatures
- [ ] Distributed verification
- [ ] A2A discovery service integration
