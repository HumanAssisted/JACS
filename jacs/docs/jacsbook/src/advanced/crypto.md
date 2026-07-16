# Cryptographic Algorithms

JACS supports multiple cryptographic algorithms for digital signatures, providing flexibility for different security requirements and future-proofing against quantum computing threats.

**`pq2025` (ML-DSA-87 / FIPS-204) is the native default.** Explicit
`ed25519` selection creates genuine Ed25519 keys and emits the canonical
`ring-Ed25519` wire label; JACS never silently substitutes one supported
algorithm for another. Every key rotation currently resolves to `pq2025`.
ES256 exists in JACS only as an ecosystem
compatibility key for targeted exports; it is never a native
`jacsSignature` algorithm. See the
[Algorithm Selection Guide](algorithm-guide.md).

## Supported Algorithms

| Algorithm | Config Value | Type | Key Size | Signature Size | Role |
|-----------|--------------|------|----------|----------------|------|
| PQ2025 | `pq2025` | ML-DSA-87 | 2,592 bytes | 4,627 bytes | Native root default; post-quantum |
| Ed25519 | `ring-Ed25519` (input: `ed25519`) | Elliptic Curve | 32 bytes | 64 bytes | Supported native creation, signing, and verification |

## Ed25519 (ring-Ed25519)

Supported for creation, signing, and verification across native bindings.

### Overview

Ed25519 is an elliptic curve signature scheme using Curve25519. JACS uses the `ring` cryptographic library implementation.

### Characteristics

- **Speed**: Extremely fast signing and verification
- **Key Size**: 32-byte private key, 32-byte public key
- **Signature Size**: 64 bytes
- **Security Level**: ~128 bits (classical)

### Configuration

```json
{
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

For user-facing CLI and SDK input, prefer `ed25519`. Configuration and signed
documents store the canonical `ring-Ed25519` wire label.

### Use Cases

- Bandwidth-sensitive or high-throughput signing
- Interoperability with existing Ed25519 identities
- Shorter-lived signatures where post-quantum resistance is not required

### Example

```python
import jacs
import json

agent, info = jacs.SimpleAgent.ephemeral(algorithm="ed25519")
assert info["algorithm"] == "ring-Ed25519"

signed = agent.sign_message({"message": "Hello, World!"})
assert json.loads(signed["raw"])["jacsSignature"]["signingAlgorithm"] == "ring-Ed25519"
```

## PQ2025

### Overview

PQ2025 uses ML-DSA-87, the FIPS-204 post-quantum signature algorithm currently supported by JACS. It is the default native root algorithm.

### Characteristics

- **Speed**: Moderate (slower than Ed25519)
- **Key Size**: 2,592-byte public keys
- **Signature Size**: 4,627 bytes
- **Security Level**: NIST Level 3 (quantum-resistant)

### Configuration

```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

### Use Cases

- Long-term document security
- Protection against future quantum attacks
- High-security applications
- Government/defense requirements

### Considerations

- Larger signatures and keys than Ed25519
- Use for compliance or long-lived signatures where post-quantum readiness matters
- May be required for future compliance

## ES256 (Compatibility Key — Never Native)

ES256 (ECDSA P-256) appears in JACS only as the **ecosystem compatibility
key** used by the targeted exporters (JWKS, DID/W3C identity, A2A agent
card, AP2 mandate, Agreement-v2 Verifiable Credential). It is never a
valid native `jacsSignature` algorithm: the signature schema permits only
`ring-Ed25519` and `pq2025`, and native verification rejects `ES256`.

An ES256 signature on an exported artifact proves possession of the
compatibility key, nothing more — it does not by itself establish native
JACS trust. The native-root-signed **compatibility key binding** is what ties
the ES256 key to the agent; see the
[Security Model](security.md#compatibility-key-binding-p2) for the
binding lifecycle. Verifying incoming AP2 mandates or third-party VCs is
out of scope in P2.

## Algorithm Selection Guide

Choose the native algorithm at agent creation. `pq2025` is the default;
`ed25519` is an explicit size/performance tradeoff.

### Decision Matrix

| Requirement | Algorithm |
|-------------|-----------|
| New agent requiring post-quantum assurance | `pq2025` (default) |
| New agent prioritizing small keys/signatures | `ed25519` (stored/emitted as `ring-Ed25519`) |
| Verifying Ed25519 documents | `ring-Ed25519` (verification is automatic) |
| JOSE/W3C ecosystem interop (JWKS, AP2, VC) | ES256 compatibility key — export-only, never native |

### By Use Case

**Web APIs and MCP**:
```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```
Native signing defaults to `pq2025`; explicitly selected Ed25519 agents remain Ed25519 until rotation.

**Legal/Financial Documents**:
```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```
Long-term validity requires quantum resistance.

**Enterprise Integration**:
```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```
Use `pq2025` where cross-organization retention or compliance expectations favor post-quantum signatures.

**High-Security**:
```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```
Belt-and-suspenders approach for maximum protection.

## Key Generation

Keys are generated automatically when creating an agent:

```bash
# Directory structure after agent creation
jacs_keys/
├── private.pem    # Algorithm-specific private key
└── public.pem     # Algorithm-specific public key
```

### Key Formats

| Algorithm | Private Key Format | Public Key Format |
|-----------|-------------------|-------------------|
| ring-Ed25519 | PEM (PKCS#8) | PEM (SPKI) |
| pq2025 | Raw ML-DSA-87 bytes | Raw ML-DSA-87 bytes |

## Signature Structure

Signatures in JACS documents include algorithm metadata:

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "date": "2024-01-15T10:30:00Z",
    "signature": "base64-encoded-signature",
    "publicKeyHash": "sha256-of-public-key",
    "signingAlgorithm": "pq2025",
    "fields": ["jacsId", "jacsVersion", "content"]
  }
}
```

The `signingAlgorithm` field enables verifiers to use the correct verification method. The native signature schema permits only `ring-Ed25519` and `pq2025`; a native document whose `signingAlgorithm` is anything else (for example `ES256`) fails verification.

## Hashing

JACS uses SHA-256 for all hash operations:

- Document content hashing (`jacsSha256`)
- Public key fingerprints (`publicKeyHash`)
- Agreement content locking (`jacsAgreementHash`)

```json
{
  "jacsSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

## Algorithm Migration

**Key rotation is the designated Ed25519 → `pq2025` migration path.**
Every rotation resolves to `pq2025` — with or without an explicit
algorithm argument — so an Ed25519 agent becomes PQ-rooted
the first time it rotates. Requesting any other rotation target is a
typed error.

1. **Rotate Keys**
   ```bash
   jacs agent rotate-keys
   ```

2. **Re-issue the Compatibility Key Binding (if present)**

   The ES256 compatibility key binding is signed by the native root, so
   rotation supersedes it. Ecosystem exports fail with a "re-issue"
   error until a new binding is signed by the current native root:
   ```bash
   jacs agent issue-compat-binding
   ```

3. **Maintain Backward Compatibility**
   - Keep old agent versions for verifying old documents
   - Old signatures remain valid with old public keys

## Performance Comparison

Approximate performance (varies by hardware):

| Algorithm | Sign (ops/sec) | Verify (ops/sec) | Key Gen (ms) |
|-----------|---------------|------------------|--------------|
| ring-Ed25519 | ~50,000 | ~20,000 | <1 |
| pq2025 | ~4,000 | ~8,000 | ~2 |

## Security Considerations

### Algorithm Agility

JACS documents include the signing algorithm, enabling:
- Verification with correct algorithm
- Graceful algorithm transitions
- Multi-algorithm environments

### Forward Secrecy

Signatures don't provide forward secrecy. For confidentiality:
- Use TLS for transport
- Consider additional encryption layers

### Key Compromise

If a private key is compromised:
1. Generate new key pair
2. Create new agent version
3. Revoke trust in compromised version
4. Re-sign critical documents

## See Also

- [Security Model](security.md) - Overall security architecture
- [Configuration](../schemas/configuration.md) - Algorithm configuration
- [DNS Verification](../dns.md) - Public key fingerprint verification
