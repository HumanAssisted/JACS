# Security Model

JACS implements a comprehensive security model designed to ensure authenticity, integrity, and non-repudiation for all agent communications and documents.

## Core Security Principles

### 1. Cryptographic Identity

Every JACS agent has a unique cryptographic identity:

- **Key Pair**: Each agent possesses a private/public key pair
- **Agent ID**: Unique UUID identifying the agent
- **Public Key Hash**: SHA-256 hash of the public key for verification

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "publicKeyHash": "sha256-of-public-key",
    "signingAlgorithm": "ring-Ed25519"
  }
}
```

### 2. Document Integrity

All documents include cryptographic guarantees:

- **Signature**: Cryptographic signature over specified fields
- **Hash**: SHA-256 hash of document contents
- **Version Tracking**: Immutable version history

### 3. Non-Repudiation

Signatures provide proof of origin:

- Agents cannot deny signing a document
- Timestamps record when signatures were made
- Public keys enable independent verification

## Threat Model

### Protected Against

| Threat | Protection |
|--------|------------|
| **Tampering** | Content hashes detect modifications |
| **Impersonation** | Cryptographic signatures verify identity |
| **Replay Attacks** | Timestamps and version IDs ensure freshness |
| **Man-in-the-Middle** | DNS verification via DNSSEC |
| **Key Compromise** | Key rotation through versioning |

### Trust Assumptions

1. Private keys are kept secure
2. Cryptographic algorithms are sound
3. DNS infrastructure (when used) is trustworthy

## Signature Process

### Signing a Document

1. **Field Selection**: Determine which fields to sign
2. **Canonicalization**: Serialize fields deterministically
3. **Signature Generation**: Sign with private key
4. **Hash Computation**: Compute SHA-256 of signed document

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create signed document
doc = agent.create_document(json.dumps({
    'title': 'Confidential Report',
    'content': 'Sensitive data here'
}))

# Document now includes jacsSignature and jacsSha256
```

### Verifying a Document

1. **Hash Verification**: Recompute hash and compare
2. **Signature Verification**: Verify signature with public key
3. **Agent Verification**: Optionally verify agent identity via DNS

```python
is_valid = agent.verify_document(doc_json)
is_signature_valid = agent.verify_signature(doc_json)
```

## Key Management

### Key Generation

JACS generates cryptographic key pairs during agent creation:

```bash
# Keys are created in the configured key directory
jacs_keys/
├── private.pem    # Private key (keep secure!)
└── public.pem     # Public key (can be shared)
```

### Key Protection

**Encryption at Rest**:

```json
{
  "jacs_private_key_password": "NEVER_STORE_IN_CONFIG"
}
```

Use environment variables instead:

```bash
export JACS_AGENT_PRIVATE_KEY_PASSWORD="secure-password"
```

**File Permissions**:

```bash
chmod 700 ./jacs_keys
chmod 600 ./jacs_keys/private.pem
```

### Key Rotation

Update agent version to rotate keys:

1. Generate new key pair
2. Create new agent version
3. Sign new version with old key
4. Update configuration to use new keys

## DNS-Based Verification

JACS supports DNSSEC-validated identity verification:

### How It Works

1. Agent publishes public key fingerprint in DNS TXT record
2. Verifier queries DNS for `_v1.agent.jacs.<domain>.`
3. DNSSEC validates the response authenticity
4. Fingerprint is compared against agent's public key

### Configuration

```json
{
  "jacs_agent_domain": "myagent.example.com",
  "jacs_dns_validate": true,
  "jacs_dns_strict": true
}
```

### Security Levels

| Mode | Description |
|------|-------------|
| `jacs_dns_validate: false` | No DNS verification |
| `jacs_dns_validate: true` | Attempt DNS verification, allow fallback |
| `jacs_dns_strict: true` | Require DNSSEC validation |
| `jacs_dns_required: true` | Fail if domain not present |

## Agreement Security

Multi-party agreements provide additional security:

### Agreement Structure

```json
{
  "jacsAgreement": {
    "agentIDs": ["agent-1", "agent-2", "agent-3"],
    "signatures": [
      {
        "agentID": "agent-1",
        "signature": "...",
        "responseType": "agree",
        "date": "2024-01-15T10:00:00Z"
      }
    ]
  },
  "jacsAgreementHash": "hash-at-agreement-time"
}
```

### Agreement Guarantees

1. **Content Lock**: `jacsAgreementHash` ensures all parties agreed to same content
2. **Individual Consent**: Each signature records explicit agreement
3. **Response Types**: Support for agree, disagree, or reject
4. **Timestamp**: Records when each party signed

## Request/Response Security

For MCP and HTTP communication:

### Request Signing

```python
signed_request = agent.sign_request({
    'method': 'tools/call',
    'params': {'name': 'echo', 'arguments': {'text': 'hello'}}
})
```

The signed request includes:
- Full JACS document structure
- Agent signature
- Timestamp
- Content hash

### Response Verification

```python
result = agent.verify_response(response_string)
payload = result.get('payload')
agent_id = result.get('agentId')  # Who signed the response
```

## Algorithm Security

### Supported Algorithms

| Algorithm | Type | Security Level |
|-----------|------|----------------|
| `ring-Ed25519` | Elliptic Curve | High (recommended) |
| `RSA-PSS` | RSA | High |
| `pq-dilithium` | Post-Quantum | Quantum-resistant |
| `pq2025` | Composite | Transitional |

### Algorithm Selection

Choose based on requirements:

- **General Use**: `ring-Ed25519` - fast, secure, small signatures
- **Legacy Systems**: `RSA-PSS` - widely supported
- **Future-Proofing**: `pq-dilithium` - quantum-resistant
- **Transition**: `pq2025` - hybrid classical/post-quantum

## Security Best Practices

### 1. Key Storage

```bash
# Never commit keys to version control
echo "jacs_keys/" >> .gitignore

# Secure file permissions
chmod 700 ./jacs_keys
chmod 600 ./jacs_keys/private.pem
```

### 2. Password Handling

```bash
# Use environment variables
export JACS_AGENT_PRIVATE_KEY_PASSWORD="$(pass show jacs/key-password)"
```

### 3. Transport Security

Always use TLS for network communication:

```python
# HTTPS for web transport
client = JACSMCPClient("https://localhost:8000/sse")  # Good
# client = JACSMCPClient("http://localhost:8000/sse")  # Avoid in production
```

### 4. Verification Policies

```json
{
  "jacs_dns_strict": true,
  "jacs_dns_required": true,
  "jacs_use_security": "1"
}
```

### 5. Audit Logging

Enable observability for security auditing:

```json
{
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info"
    }
  }
}
```

## Security Checklist

### Development

- [ ] Generate unique keys for each environment
- [ ] Never commit private keys
- [ ] Use test keys separate from production

### Production

- [ ] Encrypt private keys at rest
- [ ] Use environment variables for secrets
- [ ] Enable DNS verification
- [ ] Configure strict security mode
- [ ] Enable audit logging
- [ ] Use TLS for all network transport
- [ ] Restrict key file permissions
- [ ] Implement key rotation policy

### Verification

- [ ] Always verify documents before trusting
- [ ] Verify agent signatures
- [ ] Check agreement completeness
- [ ] Validate DNS records when required

## Security Considerations

### Supply Chain

- Verify JACS packages are from official sources
- Use package checksums
- Keep dependencies updated

### Side Channels

- Use constant-time comparison for signatures
- Protect against timing attacks
- Secure memory handling for keys

### Recovery

- Backup key material securely
- Document key recovery procedures
- Plan for key compromise scenarios

## See Also

- [Cryptographic Algorithms](crypto.md) - Algorithm details
- [DNS Verification](../dns.md) - DNS-based identity
- [Configuration](../schemas/configuration.md) - Security configuration
- [Agreements](../rust/agreements.md) - Multi-party agreements
