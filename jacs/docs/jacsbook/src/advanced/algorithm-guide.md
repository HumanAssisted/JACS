# Algorithm Selection Guide

Choosing the right signing algorithm affects key size, signature size, verification speed, and compliance posture. This guide helps you pick the right one.

## Supported Algorithms

| Algorithm | Config Value | Public Key | Signature | Best For |
|-----------|-------------|------------|-----------|----------|
| Ed25519 | `ring-Ed25519` | 32 bytes | 64 bytes | Speed, small signatures |
| RSA-PSS | `RSA-PSS` | ~550 bytes (4096-bit) | ~512 bytes | Broad compatibility |
| ML-DSA-87 | `pq2025` | 2,592 bytes | 4,627 bytes | Post-quantum compliance (FIPS-204) |
| Dilithium | `pq-dilithium` | >1,000 bytes | ~3,293-4,644 bytes | **Deprecated** -- use `pq2025` |

## How to Choose

```
Do you need FIPS/NIST post-quantum compliance?
  ├── Yes → pq2025
  └── No
       ├── Need maximum interop with existing PKI/TLS systems? → RSA-PSS
       └── Need speed and small payloads? → ring-Ed25519
```

**Default recommendation for new projects: `pq2025`**

Ed25519 and RSA-PSS are well-understood and widely deployed, but neither is quantum-resistant. If you don't have a specific reason to choose one of them, start with `pq2025` so you don't have to migrate later.

## When to Choose Post-Quantum

Choose `pq2025` (ML-DSA-87, FIPS-204) when:

- Your compliance team asks about quantum readiness
- Government or defense contracts require FIPS-204
- You need long-lived signatures that must remain valid for 10+ years
- You want to avoid a future algorithm migration

JACS supports ML-DSA-87 (FIPS-204) for post-quantum digital signatures. When your compliance team asks about quantum readiness, JACS already has the answer.

The tradeoff is size: ML-DSA-87 public keys are 2,592 bytes and signatures are 4,627 bytes -- roughly 80x larger than Ed25519. For most applications this is negligible, but if you're signing millions of small messages and bandwidth matters, consider Ed25519.

## Cross-Algorithm Verification

JACS verification works across algorithms. An agreement can contain signatures from RSA, Ed25519, and ML-DSA agents and all verify correctly. This heterogeneous verification is important for cross-organization scenarios where different parties chose different algorithms.

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

Valid values: `ring-Ed25519`, `RSA-PSS`, `pq2025`, `pq-dilithium`

In Python and Node.js, pass the algorithm to `quickstart()`:

```python
from jacs.client import JacsClient
client = JacsClient.quickstart(algorithm="pq2025")
```

```typescript
import { JacsClient } from "@hai.ai/jacs";
const client = await JacsClient.quickstart({ algorithm: "pq2025" });
```

## Current Limitations

- Each agent uses one algorithm, chosen at creation time. You cannot change an agent's algorithm after creation.
- Algorithm negotiation between agents is planned but not yet implemented.
- `pq-dilithium` is deprecated in favor of `pq2025` (ML-DSA-87). It remains available for backward compatibility but should not be used for new agents.
