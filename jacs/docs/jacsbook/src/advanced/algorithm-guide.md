# Algorithm Selection Guide

Choosing the right signing algorithm affects key size, signature size, verification speed, and compliance posture. This guide helps you pick the right one.

## New Agents Are PQ-Only

**New agent creation always uses `pq2025` (ML-DSA-87 / FIPS-204).** There is no
algorithm choice at creation time: a request for Ed25519 (via config or an
explicit parameter) resolves to `pq2025` and logs a WARN; ES256 or any other
algorithm is a typed error. ES256 exists in JACS only as an ecosystem
compatibility key, never as a native `jacsSignature` algorithm.

Existing Ed25519-rooted agents are **grandfathered**: they continue to load,
sign (each native signature logs a WARN `native_legacy_ed25519_sign`), and
verify. All key rotations resolve to `pq2025`, so a grandfathered agent
migrates to post-quantum keys the first time it rotates — see
[Key Rotation](key-rotation.md).

## Supported Algorithms

| Algorithm | Config Value | Public Key | Signature | Status |
|-----------|-------------|------------|-----------|--------|
| ML-DSA-87 | `pq2025` | 2,592 bytes | 4,627 bytes | Default and only algorithm for new agents (FIPS-204) |
| Ed25519 | `ring-Ed25519` | 32 bytes | 64 bytes | Legacy: verify always; sign only for grandfathered pre-existing agents |

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

Valid values for new keys: `ring-Ed25519`, `pq2025`

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
