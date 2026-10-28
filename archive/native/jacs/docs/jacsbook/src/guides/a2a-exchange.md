# Exchange Signed Artifacts

Sign artifacts with cryptographic provenance and verify artifacts from other agents. Node.js snippets run inside an async function. For multi-agent examples, create separate clients/configurations and independently authenticate each signer's public evidence and configure the verifier's key resolver before verification. Native artifact verification uses its local public-key cache or registry; trust-store enrollment alone does not populate that cache. See [cross-agent setup](a2a-attestation-composition.md).

<div class="tabs">
<div class="tab">
<input type="radio" id="sign-python" name="sign-group" checked>
<label for="sign-python">Python</label>
<div class="content">

### Sign and Verify

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")

# Sign an artifact
signed = client.sign_artifact({"action": "classify", "input": "data"}, "artifact")

# Verify it (with trust assessment)
a2a = client.get_a2a()
result = a2a.verify_wrapped_artifact(signed, assess_trust=True)
print(f"Valid: {result['valid']}, Allowed: {result['trust']['allowed']}")
```

### Chain of Custody

When multiple agents process data in sequence, link artifacts into a verifiable chain:

```python
# Agent A signs step 1
step1 = client_a.sign_artifact({"step": 1, "data": "raw"}, "artifact")

# Agent B signs step 2, referencing step 1 as parent
step2 = client_b.sign_artifact(
    {"step": 2, "data": "processed"},
    "artifact",
    parent_signatures=[step1],
)

# Verify the full chain
result = a2a.verify_wrapped_artifact(step2)
assert result["valid"]
assert result["parent_signatures_valid"]
```

### Build an Audit Trail

```python
chain = a2a.create_chain_of_custody([step1, step2])
# Metadata only: chainOfCustody, created, totalArtifacts.
# This helper does not verify signatures, ordering or validity.
```

</div>
</div>

<div class="tab">
<input type="radio" id="sign-nodejs" name="sign-group">
<label for="sign-nodejs">Node.js</label>
<div class="content">

### Sign and Verify

```javascript
const { JacsClient } = require('@hai.ai/jacs/client');

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});

// Sign an artifact
const signed = await client.signArtifact({ action: 'classify', input: 'data' }, 'task');

// Verify it
const a2a = client.getA2A();
const result = a2a.verifyWrappedArtifact(signed);
console.log(`Valid: ${result.valid}`);
```

### Chain of Custody

```javascript
// Agent A signs step 1
const step1 = await clientA.signArtifact({ step: 1, data: 'raw' }, 'message');

// Agent B signs step 2, referencing step 1
const step2 = await clientB.signArtifact(
  { step: 2, data: 'processed' }, 'message', [step1],
);

// Verify the full chain
const result = a2a.verifyWrappedArtifact(step2);
console.log(`Chain valid: ${result.valid}`);
console.log(`Parents valid: ${result.parentSignaturesValid}`);
```

</div>
</div>
</div>

## Artifact Types

The `artifact_type` parameter labels the payload for downstream processing:

| Type | Use Case |
|------|----------|
| `task` | Task assignments, work requests |
| `message` | Inter-agent messages |
| `result` | Task results, responses |

You can use any string -- these are conventions, not enforced types.

## What Gets Signed

Every signed artifact includes:

| Field | Description |
|-------|-------------|
| `jacsId` | Unique document ID |
| `jacsSignature` | Signer ID, algorithm, timestamp, and base64 signature |
| `jacsSha256` | Content hash for integrity verification |
| `jacsType` | `a2a-` followed by the caller's artifact type label |
| `jacsParentSignatures` | Parent artifacts for chain of custody (if any) |
| `a2aArtifact` | The original artifact data |

Extract `a2aArtifact` only after the required signature and trust checks. Discarding the envelope also discards its provenance.

## Next Steps

- **[Serve Your Agent Card](a2a-serve.md)** -- Make your agent discoverable
- **[Discover & Trust Remote Agents](a2a-discover.md)** -- Find and assess other agents
- **[A2A Interoperability Reference](../integrations/a2a.md)** -- Full API reference
- **[Hero Demo (Python)](https://github.com/HumanAssisted/JACS/blob/main/archive/native/examples/a2a_trust_demo.py)** -- 3-agent trust verification example
