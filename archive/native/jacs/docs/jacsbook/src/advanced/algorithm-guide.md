# Algorithm Selection Guide

Choosing the right signing algorithm affects key size, signature size, verification speed, and compliance posture. This guide helps you pick the right one.

## New-Agent Selection

**`pq2025` (ML-DSA-87 / FIPS-204) is the secure default.** Pass `ed25519`
explicitly when its smaller keys and signatures are required. JACS returns the
canonical wire label `ring-Ed25519`; the requested label, generated key shape,
persisted configuration, and emitted signature algorithm always agree.
`ring-Ed25519` remains accepted as a legacy input alias. ES256 is an ecosystem
compatibility key, never a native `jacsSignature` algorithm.

All key rotations currently resolve to `pq2025`, so rotation is also the
supported Ed25519-to-post-quantum migration path — see
[Key Rotation](key-rotation.md).

## Supported Algorithms

| Algorithm | Config Value | Public Key | Signature | Status |
|-----------|-------------|------------|-----------|--------|
| ML-DSA-87 | `pq2025` | 2,592 bytes | 4,627 bytes | Default; post-quantum (FIPS-204) |
| Ed25519 | `ring-Ed25519` (input alias: `ed25519`) | 32 bytes | 64 bytes | Supported for creation, signing, and verification |

## When to Choose Post-Quantum

Choose `pq2025` (ML-DSA-87, FIPS-204) when:

- Your compliance team asks about quantum readiness
- Government or defense contracts require FIPS-204
- You need long-lived signatures that must remain valid for 10+ years
- You want to avoid a future algorithm migration

JACS supports ML-DSA-87 (FIPS-204) for post-quantum digital signatures. When your compliance team asks about quantum readiness, JACS already has the answer.

The tradeoff is size: ML-DSA-87 public keys are 2,592 bytes and signatures are 4,627 bytes -- roughly 80x larger than Ed25519. For most applications this is negligible, but if you're signing millions of small messages and bandwidth matters, consider Ed25519.

## Cross-Algorithm Verification

JACS verification works across supported algorithms. An agreement can contain signatures from Ed25519 and ML-DSA agents and all verify correctly. This heterogeneous verification is important for cross-organization scenarios where different parties choose different supported algorithms.

Each agent uses one algorithm (chosen at creation time), but can **verify** signatures from all supported algorithms.

## Configuration

Set the algorithm in your `jacs.config.json`:

```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

Or via environment variable:

```bash
export JACS_AGENT_KEY_ALGORITHM=pq2025
```

User-facing values for new keys: `ed25519`, `pq2025`. The historical
`ring-Ed25519` input remains accepted and is the canonical signature/config
label emitted for Ed25519.

In Python and Node.js, pass the algorithm to `quickstart(...)`:

```python
from jacs.client import JacsClient
client = JacsClient.quickstart(
    name="algo-agent",
    domain="algo.example.com",
    algorithm="pq2025",
)
```

```typescript
import { JacsClient } from "@hai.ai/jacs";
const client = await JacsClient.quickstart({
  name: "algo-agent",
  domain: "algo.example.com",
  algorithm: "pq2025",
});
```

## Current Limitations

- Each agent uses one algorithm, chosen at creation time. You cannot change an agent's algorithm after creation.
- Algorithm negotiation between agents is planned but not yet implemented.
- Use `pq2025` for ML-DSA-87 post-quantum signatures and verification hints.
