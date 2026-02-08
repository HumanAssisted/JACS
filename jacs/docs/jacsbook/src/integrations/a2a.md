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

## Python Example

```python
from jacs.a2a import JACSA2AIntegration

a2a = JACSA2AIntegration("jacs.config.json")
agent_card = a2a.export_agent_card(agent_data)
docs = a2a.generate_well_known_documents(
    agent_card=agent_card,
    jws_signature="...",
    public_key_b64="...",
    agent_data={"jacsId": "...", "jacsVersion": "...", "keyAlgorithm": "RSA-PSS"},
)

assert "/.well-known/jwks.json" in docs
```

## Node.js Example

```javascript
const { JACSA2AIntegration } = require('@hai-ai/jacs/a2a');

const a2a = new JACSA2AIntegration('./jacs.config.json');
const wrapped = a2a.wrapArtifactWithProvenance(
  { taskId: 'task-123', operation: 'classify' },
  'task'
);

const result = a2a.verifyWrappedArtifact(wrapped);
console.log(result.valid, result.parentSignaturesValid);
```

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
