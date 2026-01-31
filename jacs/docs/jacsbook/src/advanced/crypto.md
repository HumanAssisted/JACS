# Cryptographic Algorithms

JACS supports multiple cryptographic algorithms for digital signatures, providing flexibility for different security requirements and future-proofing against quantum computing threats.

## Supported Algorithms

| Algorithm | Config Value | Type | Key Size | Signature Size | Recommended Use |
|-----------|--------------|------|----------|----------------|-----------------|
| Ed25519 | `ring-Ed25519` | Elliptic Curve | 32 bytes | 64 bytes | General purpose (default) |
| RSA-PSS | `RSA-PSS` | RSA | 2048-4096 bits | 256-512 bytes | Legacy systems |
| Dilithium | `pq-dilithium` | Lattice-based | ~1.3 KB | ~2.4 KB | Post-quantum |
| PQ2025 | `pq2025` | Hybrid | ~1.3 KB | ~2.5 KB | Transitional |

## Ed25519 (ring-Ed25519)

The recommended algorithm for most use cases.

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

### Use Cases

- General agent communication
- MCP message signing
- HTTP request/response signing
- Document signing

### Example

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')  # Using ring-Ed25519

# Sign a message
signature = agent.sign_string("Hello, World!")
print(f"Signature (64 bytes): {len(signature)} characters base64")
```

## RSA-PSS

Industry-standard RSA with Probabilistic Signature Scheme padding.

### Overview

RSA-PSS provides compatibility with systems that require RSA signatures. JACS uses 2048-bit or larger keys.

### Characteristics

- **Speed**: Slower than Ed25519
- **Key Size**: 2048-4096 bits
- **Signature Size**: Same as key size (256-512 bytes)
- **Security Level**: ~112-128 bits (2048-bit key)

### Configuration

```json
{
  "jacs_agent_key_algorithm": "RSA-PSS"
}
```

### Use Cases

- Integration with legacy systems
- Compliance requirements mandating RSA
- Interoperability with enterprise PKI

### Considerations

- Larger signatures increase document size
- Slower than Ed25519
- Larger keys needed for equivalent security

## Dilithium (pq-dilithium)

NIST-standardized post-quantum digital signature algorithm.

### Overview

Dilithium is a lattice-based signature scheme selected by NIST for post-quantum cryptography standardization. It provides security against both classical and quantum computers.

### Characteristics

- **Speed**: Moderate (faster than RSA, slower than Ed25519)
- **Key Size**: ~1.3 KB public key, ~2.5 KB private key
- **Signature Size**: ~2.4 KB
- **Security Level**: NIST Level 3 (quantum-resistant)

### Configuration

```json
{
  "jacs_agent_key_algorithm": "pq-dilithium"
}
```

### Use Cases

- Long-term document security
- Protection against future quantum attacks
- High-security applications
- Government/defense requirements

### Considerations

- Larger signatures and keys than classical algorithms
- Newer algorithm (less battle-tested)
- May be required for future compliance

## PQ2025 (Hybrid)

Transitional hybrid scheme combining classical and post-quantum algorithms.

### Overview

PQ2025 combines Ed25519 with Dilithium, providing security even if one algorithm is broken. This approach is recommended by security researchers during the quantum transition period.

### Characteristics

- **Speed**: Slower (two signatures computed)
- **Key Size**: Combined Ed25519 + Dilithium
- **Signature Size**: ~2.5 KB (combined)
- **Security Level**: Max of both algorithms

### Configuration

```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

### Use Cases

- Transitioning to post-quantum
- Maximum security requirements
- Uncertainty about algorithm security
- Long-lived documents

### Considerations

- Largest signatures
- Slowest signing/verification
- Best for paranoid security requirements

## Algorithm Selection Guide

### Decision Matrix

| Requirement | Recommended Algorithm |
|-------------|----------------------|
| Best performance | `ring-Ed25519` |
| Smallest signatures | `ring-Ed25519` |
| Legacy compatibility | `RSA-PSS` |
| Quantum resistance | `pq-dilithium` |
| Maximum security | `pq2025` |
| General purpose | `ring-Ed25519` |

### By Use Case

**Web APIs and MCP**:
```json
{
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```
Fast signing is critical for real-time communication.

**Legal/Financial Documents**:
```json
{
  "jacs_agent_key_algorithm": "pq-dilithium"
}
```
Long-term validity requires quantum resistance.

**Enterprise Integration**:
```json
{
  "jacs_agent_key_algorithm": "RSA-PSS"
}
```
Compatibility with existing PKI infrastructure.

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
| RSA-PSS | PEM (PKCS#8) | PEM (SPKI) |
| pq-dilithium | PEM (custom) | PEM (custom) |
| pq2025 | PEM (combined) | PEM (combined) |

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
    "signingAlgorithm": "ring-Ed25519",
    "fields": ["jacsId", "jacsVersion", "content"]
  }
}
```

The `signingAlgorithm` field enables verifiers to use the correct verification method.

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

To migrate to a new algorithm:

1. **Generate New Keys**
   ```json
   {
     "jacs_agent_key_algorithm": "pq-dilithium"
   }
   ```

2. **Create New Agent Version**
   ```python
   # Load with old algorithm
   agent.load('./old-config.json')

   # Update to new algorithm and generate new version
   new_agent = agent.update_agent(json.dumps({
       # ... agent data with new keys
   }))
   ```

3. **Update Configuration**
   ```json
   {
     "jacs_agent_id_and_version": "agent-id:new-version",
     "jacs_agent_key_algorithm": "pq-dilithium"
   }
   ```

4. **Maintain Backward Compatibility**
   - Keep old agent versions for verifying old documents
   - Old signatures remain valid with old public keys

## Performance Comparison

Approximate performance (varies by hardware):

| Algorithm | Sign (ops/sec) | Verify (ops/sec) | Key Gen (ms) |
|-----------|---------------|------------------|--------------|
| ring-Ed25519 | ~50,000 | ~20,000 | <1 |
| RSA-PSS (2048) | ~1,000 | ~30,000 | ~100 |
| pq-dilithium | ~5,000 | ~10,000 | ~1 |
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
