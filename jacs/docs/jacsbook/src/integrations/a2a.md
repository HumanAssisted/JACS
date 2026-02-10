# A2A Interoperability

This guide describes how JACS interoperates with Agent-to-Agent (A2A) systems in real deployments.

## What JACS Adds

JACS adds cryptographic provenance to A2A artifacts:

- Signed artifact envelopes (`a2a-task`, `a2a-message`, etc.)
- Verifiable signer identity via public key resolution
- Chain-of-custody support through parent signatures
- Well-known discovery documents for external verifiers

## Interoperability Contract

JACS A2A integration currently targets the v0.4.0 Agent Card shape used in this repository's Rust, Python, and Node bindings.

Required well-known documents:

- `/.well-known/agent-card.json`
- `/.well-known/jwks.json`
- `/.well-known/jacs-agent.json`
- `/.well-known/jacs-pubkey.json`

## Verification Model

When verifying foreign-agent A2A artifacts, JACS resolves keys using `JACS_KEY_RESOLUTION` order:

- `local`: trusted local key cache
- `dns`: identity validation only (does not return key bytes)
- `hai`: remote key retrieval from HAI key service

If a key is found, JACS performs full signature verification and returns a verified status.
If no key is found, verification is explicitly marked unverified (not silently accepted).

## 12-Factor Runtime Configuration

Use environment variables for deploy-time behavior:

```bash
export JACS_PRIVATE_KEY_PASSWORD="your-strong-password"
export JACS_KEY_RESOLUTION="local,hai"
export HAI_KEYS_BASE_URL="https://keys.hai.ai"
```

For offline/air-gapped operation:

```bash
export JACS_KEY_RESOLUTION="local"
```

## Rust Example

```rust
use jacs::a2a::provenance::{wrap_artifact_with_provenance, verify_wrapped_artifact};
use serde_json::json;

let wrapped = wrap_artifact_with_provenance(
    &mut agent,
    json!({"taskId": "task-123", "operation": "classify"}),
    "task",
    None,
)?;

let result = verify_wrapped_artifact(&agent, &wrapped)?;
assert!(result.valid);
```

## Python: `JACSA2AIntegration` Class

The `jacs.a2a` module provides the `JACSA2AIntegration` class (`jacspy/python/jacs/a2a.py`) which handles the full A2A lifecycle: agent card export, artifact signing, verification, chain-of-custody, and well-known document generation.

### Create an A2A-Compatible Agent Card

Export your JACS agent as a v0.4.0 A2A Agent Card. JACS services are automatically converted to A2A skills, and a `urn:hai.ai:jacs-provenance-v1` extension is declared in capabilities.

```python
from jacs.a2a import JACSA2AIntegration
import json

a2a = JACSA2AIntegration("jacs.config.json")

agent_data = {
    "jacsId": "agent-abc-123",
    "jacsVersion": "v1.0.0",
    "jacsName": "Analysis Agent",
    "jacsDescription": "Performs text analysis",
    "jacsAgentType": "ai",
    "jacsAgentDomain": "agents.example.com",
    "jacsServices": [{
        "name": "Text Analysis",
        "serviceDescription": "Analyzes text using NLP",
        "tools": [{
            "function": {
                "name": "analyze_text",
                "description": "Analyze text and extract insights",
                "parameters": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]
                }
            }
        }]
    }]
}

agent_card = a2a.export_agent_card(agent_data)
# agent_card.name == "Analysis Agent"
# agent_card.skills[0].id == "analyze-text"
# agent_card.capabilities.extensions[0].uri == "urn:hai.ai:jacs-provenance-v1"
```

### Publish `/.well-known/agent.json`

Generate all five well-known documents for A2A discovery:

```python
docs = a2a.generate_well_known_documents(
    agent_card=agent_card,
    jws_signature="eyJhbGciOi...",  # JWS of the agent card
    public_key_b64="MIIBIjANBg...",
    agent_data=agent_data,
)

# docs contains:
#   /.well-known/agent-card.json   -- A2A Agent Card with embedded JWS signature
#   /.well-known/jwks.json         -- JWK Set for external verifiers
#   /.well-known/jacs-agent.json   -- JACS agent descriptor (signing capabilities)
#   /.well-known/jacs-pubkey.json  -- Public key + hash + algorithm
#   /.well-known/jacs-extension.json -- JACS provenance extension descriptor
```

Serve these from any web framework:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse

app = Starlette()

for path, content in docs.items():
    # Create a route for each well-known document
    app.add_route(path, lambda req, c=content: JSONResponse(c))
```

### Sign and Verify A2A Artifacts

Wrap any A2A artifact (task, message, etc.) with a JACS provenance signature:

```python
task = {"taskId": "task-456", "operation": "classify", "input": {"text": "hello"}}
wrapped = a2a.wrap_artifact_with_provenance(task, "task")
# wrapped contains: jacsId, jacsVersion, jacsSignature, a2aArtifact, ...

result = a2a.verify_wrapped_artifact(wrapped)
assert result["valid"]
assert result["artifact_type"] == "a2a-task"
assert result["original_artifact"] == task
```

### Chain of Custody for Multi-Agent Workflows

Build a provenance chain when artifacts pass between agents:

```python
# Agent A signs step 1
step1 = a2a.wrap_artifact_with_provenance(
    {"step": 1, "data": "raw_input"}, "message"
)

# Agent B signs step 2, referencing step 1 as a parent
step2 = a2a.wrap_artifact_with_provenance(
    {"step": 2, "data": "processed"},
    "message",
    parent_signatures=[step1],  # chain of custody
)

# Verify the full chain (recursive parent verification)
result = a2a.verify_wrapped_artifact(step2)
assert result["valid"]
assert result["parent_signatures_valid"]  # all parent sigs verified

# Generate audit trail
chain = a2a.create_chain_of_custody([step1, step2])
# chain["totalArtifacts"] == 2
# chain["chainOfCustody"][0]["agentId"] == signer of step1
```

### Cross-Organization Trust via Discovery

To discover and verify a remote agent from another organization:

1. Fetch their `/.well-known/agent-card.json`
2. Verify the embedded JWS signature using their `/.well-known/jwks.json`
3. Check the `urn:hai.ai:jacs-provenance-v1` extension for JACS compatibility
4. Use `JACS_KEY_RESOLUTION` to resolve their public key and verify artifacts

## Rust Example

```rust
use jacs::a2a::provenance::{wrap_artifact_with_provenance, verify_wrapped_artifact};
use serde_json::json;

let wrapped = wrap_artifact_with_provenance(
    &mut agent,
    json!({"taskId": "task-123", "operation": "classify"}),
    "task",
    None,
)?;

let result = verify_wrapped_artifact(&agent, &wrapped)?;
assert!(result.valid);
```

## Node.js Example

```javascript
const { JACSA2AIntegration } = require('@hai.ai/jacs/a2a');

const a2a = new JACSA2AIntegration('./jacs.config.json');
const wrapped = a2a.wrapArtifactWithProvenance(
  { taskId: 'task-123', operation: 'classify' },
  'task'
);

const result = a2a.verifyWrappedArtifact(wrapped);
console.log(result.valid, result.parentSignaturesValid);
```

## `JACSA2AIntegration` API Reference

| Method | Description |
|--------|-------------|
| `export_agent_card(agent_data)` | Convert JACS agent data to `A2AAgentCard` dataclass |
| `agent_card_to_dict(card)` | Serialize `A2AAgentCard` to camelCase dict for JSON |
| `generate_well_known_documents(...)` | Generate all 5 `.well-known` documents |
| `wrap_artifact_with_provenance(artifact, type, parents)` | Sign an A2A artifact with JACS provenance |
| `verify_wrapped_artifact(wrapped)` | Verify signature + recursive parent chain |
| `create_chain_of_custody(artifacts)` | Build audit trail from signed artifacts |
| `create_extension_descriptor()` | Return JACS extension descriptor for A2A |

## DevEx Expectations

Before merging A2A changes, ensure:

1. Rust, Python, and Node A2A tests all pass.
2. Foreign-signature verification is covered by tests (resolved and unresolved key paths).
3. Documentation snippets match package names and executable APIs.
4. Well-known docs include `jwks.json` and match output from all bindings.

## Troubleshooting

- `Unverified` foreign signatures: no signer key available from configured resolution order.
- `Invalid` signatures: signature bytes, signer key, or signed payload fields do not match.
- Missing `jwks.json`: ensure you are using current A2A helper APIs in your binding.
- `Cycle detected`: parent signature chain has a circular reference. Each artifact's `jacsId` must be unique.
