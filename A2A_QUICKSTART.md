# JACS A2A Quick Start Guide

JACS extends Google's A2A (Agent-to-Agent) protocol with cryptographic document provenance.

## What JACS Adds to A2A

- **Document signatures** that persist with data (not just transport security)
- **Post-quantum cryptography** for future-proof security  
- **Chain of custody** tracking for multi-agent workflows
- **Self-verifying artifacts** that work offline

## Installation

```bash
# Rust
cargo add jacs

# Python
pip install jacs

# Node.js
npm install jacsnpm
```

## Basic Usage

### 1. Export Agent to A2A Format

```python
from jacs.a2a import JACSA2AIntegration

a2a = JACSA2AIntegration("jacs.config.json")
agent_card = a2a.export_agent_card({
    "jacsId": "my-agent",
    "jacsName": "My Agent",
    "jacsServices": [{
        "name": "Process Data",
        "tools": [{
            "url": "/api/process",
            "function": {
                "name": "process",
                "description": "Process data"
            }
        }]
    }]
})
```

### 2. Wrap A2A Artifacts with Provenance

```javascript
const { JACSA2AIntegration } = require('jacsnpm');
const a2a = new JACSA2AIntegration();

// Wrap any A2A artifact
const wrapped = a2a.wrapArtifactWithProvenance({
    taskId: 'task-123',
    operation: 'analyze',
    data: { /* ... */ }
}, 'task');
```

### 3. Verify Wrapped Artifacts

```rust
use jacs::a2a::provenance::verify_wrapped_artifact;

let result = verify_wrapped_artifact(&agent, &wrapped_artifact)?;
if result.valid {
    println!("Verified by: {}", result.signer_id);
}
```

### 4. Create Chain of Custody

```python
# Track multi-step workflows
step1 = a2a.wrap_artifact_with_provenance(data1, "step")
step2 = a2a.wrap_artifact_with_provenance(data2, "step", [step1])
step3 = a2a.wrap_artifact_with_provenance(data3, "step", [step2])

chain = a2a.create_chain_of_custody([step1, step2, step3])
```

## Well-Known Endpoints

Serve these endpoints for A2A discovery:

- `/.well-known/agent.json` - A2A Agent Card (JWS signed)
- `/.well-known/jacs-agent.json` - JACS agent descriptor
- `/.well-known/jacs-pubkey.json` - JACS public key

## JACS Extension in Agent Cards

```json
{
  "capabilities": {
    "extensions": [{
      "uri": "urn:hai.ai:jacs-provenance-v1",
      "description": "JACS cryptographic document signing",
      "params": {
        "supportedAlgorithms": ["dilithium", "rsa", "ecdsa"],
        "verificationEndpoint": "/jacs/verify"
      }
    }]
  }
}
```

## Examples

- **Rust**: [jacs/examples/a2a_complete_example.rs](./jacs/examples/a2a_complete_example.rs)
- **Python**: [jacspy/examples/fastmcp/a2a_agent_server.py](./jacspy/examples/fastmcp/a2a_agent_server.py)
- **Node.js**: [jacsnpm/examples/a2a-agent-example.js](./jacsnpm/examples/a2a-agent-example.js)

## Key Concepts

1. **Dual Keys**: JACS generates two key pairs:
   - Post-quantum (Dilithium) for document signatures
   - Traditional (RSA/ECDSA) for A2A compatibility

2. **Separation of Concerns**:
   - A2A handles discovery and transport
   - JACS handles document provenance

3. **Zero Trust**: Every artifact is self-verifying with complete audit trail

## Next Steps

1. Set up JACS configuration with keys
2. Export your agent as A2A Agent Card
3. Implement verification endpoints
4. Register with A2A discovery services

See full documentation: [jacs/src/a2a/README.md](./jacs/src/a2a/README.md)
