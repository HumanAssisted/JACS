# A2A + Attestation: Using Both Together

A2A provenance and attestation serve different purposes. This guide explains when and how to combine them.

## When You Need Both

Use A2A alone when you need to prove *who sent what* across agent boundaries. Use attestation alone when you need to record *why data should be trusted* within a single agent's workflow.

Use both when:
- You send data to another agent AND need to explain why it's trustworthy
- You receive data from another agent AND want to attest that you reviewed it
- You're building a multi-agent pipeline where each step adds trust evidence

## The Composition Rule

> **A2A chain-of-custody provides movement lineage. Attestation derivation provides claim lineage.**

A2A tracks *where* an artifact has been (Agent A → Agent B → Agent C). Attestation tracks *what trust claims* have been made about it (scanned → reviewed → approved).

They compose naturally: an agent receives a signed artifact via A2A, then creates an attestation recording its analysis of that artifact.

## Example Workflow

```
Agent A: Signs artifact with A2A provenance
    ↓ (cross-boundary exchange)
Agent B: Verifies A2A signature, attests review with evidence
    ↓ (cross-boundary exchange)
Agent C: Verifies both the A2A chain and the attestation
```

### Python

```python
from jacs.client import JacsClient

# --- Agent A: Sign and send ---
agent_a = JacsClient.quickstart(name="scanner", domain="scanner.example.com")
a2a_a = agent_a.get_a2a()
signed = a2a_a.sign_artifact(
    {"scan_result": "clean", "target": "file.bin"},
    "message",
)

# --- Agent B: Receive, verify, attest ---
agent_b = JacsClient.quickstart(name="reviewer", domain="reviewer.example.com")
a2a_b = agent_b.get_a2a()

# Verify the A2A artifact from Agent A
verify_result = a2a_b.verify_wrapped_artifact(signed)
assert verify_result["valid"]

# Now attest WHY the review is trustworthy
import hashlib, json
content_hash = hashlib.sha256(json.dumps(signed, sort_keys=True).encode()).hexdigest()
attestation = agent_b.create_attestation(
    subject={"type": "artifact", "id": signed["jacsId"], "digests": {"sha256": content_hash}},
    claims=[{"name": "reviewed", "value": True, "confidence": 0.9}],
)

# Send the attestation onward via A2A
attested_artifact = a2a_b.sign_artifact(
    {"attestation_id": attestation.document_id, "original_artifact": signed["jacsId"]},
    "message",
    parent_signatures=[signed],
)
```

### Node.js

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

// --- Agent A: Sign and send ---
const agentA = await JacsClient.quickstart({ name: 'scanner', domain: 'scanner.example.com' });
const a2aA = agentA.getA2A();
const signed = await a2aA.signArtifact(
  { scanResult: 'clean', target: 'file.bin' },
  'message',
);

// --- Agent B: Receive, verify, attest ---
const agentB = await JacsClient.quickstart({ name: 'reviewer', domain: 'reviewer.example.com' });
const a2aB = agentB.getA2A();

const verifyResult = await a2aB.verifyWrappedArtifact(signed);
console.assert(verifyResult.valid);

// Attest the review
const attestation = agentB.createAttestation({
  subject: { type: 'artifact', id: signed.jacsId, digests: { sha256: '...' } },
  claims: [{ name: 'reviewed', value: true, confidence: 0.9 }],
});
```

## What NOT to Do

- **Don't use A2A trust policy to validate attestation evidence.** A2A policy (`open`/`verified`/`strict`) controls agent admission, not evidence quality. An `allowed` agent can still produce bad evidence.
- **Don't use attestation to determine transport trust.** Attestation claims don't tell you whether an agent should be allowed to communicate. Use `assess_remote_agent()` for that.
- **Don't conflate chain-of-custody with derivation chain.** A2A parent signatures track artifact movement. Attestation derivation tracks how one claim was produced from another. They are complementary, not interchangeable.

## Further Reading

- [Trust Layers](../getting-started/trust-layers.md) — the three-layer model and terminology
- [A2A Interoperability](../integrations/a2a.md) — full A2A reference
- [Attestation Tutorial](../guides/attestation-tutorial.md) — creating and verifying attestations
- [Sign vs. Attest](../guides/sign-vs-attest.md) — choosing the right API
