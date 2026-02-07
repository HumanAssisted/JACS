# Security Model

JACS implements a comprehensive security model designed to ensure authenticity, integrity, and non-repudiation for all agent communications and documents.

## Security Model (v0.6.0)

- **Passwords**: The private key password must be set only via the `JACS_PRIVATE_KEY_PASSWORD` environment variable. It is never stored in config files.
- **Keys**: Private keys are encrypted at rest (AES-256-GCM with PBKDF2, 600k iterations). Public keys and config may be stored on disk.
- **Path validation**: All paths built from untrusted input (e.g. `publicKeyHash`, filenames) are validated via `require_relative_path_safe()` to prevent directory traversal. This single validation function is used in data and key directory path builders and the trust store.
- **No secrets in config**: Config files must not contain passwords or other secrets. The example config (`jacs.config.example.json`) does not include `jacs_private_key_password`.
- **Dependency auditing**: Run `cargo audit` (Rust), `npm audit` (Node.js), or `pip audit` (Python) to check for known vulnerabilities.

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
| **Replay Attacks** | Timestamps and version IDs ensure freshness; future timestamps rejected; optional signature expiration via `JACS_MAX_SIGNATURE_AGE_SECONDS` |
| **Man-in-the-Middle** | DNS verification via DNSSEC; TLS certificate validation |
| **Key Compromise** | Key rotation through versioning |
| **Weak Passwords** | Minimum 28-bit entropy enforcement (35-bit for single class) |

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

Private keys are encrypted using AES-256-GCM with a key derived via PBKDF2-HMAC-SHA256 (600,000 iterations). Never store the password in config files.

```bash
# Set via environment variable only
export JACS_PRIVATE_KEY_PASSWORD="secure-password"
```

> **Important**: The CLI can prompt for the password during `jacs init`, but scripts and servers must set `JACS_PRIVATE_KEY_PASSWORD` as an environment variable.

**Password Entropy Requirements**:

JACS enforces password entropy minimums for private key encryption. Password validation is performed at encryption time, and weak passwords are rejected with helpful error messages:

- Minimum **28-bit entropy** for passwords with 2+ character classes (mixed case, numbers, symbols)
- Minimum **35-bit entropy** for single-character-class passwords (e.g., all lowercase)
- Entropy is calculated based on character class diversity and length
- Weak passwords result in immediate rejection during key encryption
- Error messages guide users toward stronger password choices

Example of rejected weak passwords:
- `password` - Too common and predictable
- `12345678` - Insufficient character diversity
- `abc` - Too short

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

## TLS Certificate Validation

JACS includes configurable TLS certificate validation for secure network communication.

### Default Behavior (Development)

By default, JACS warns about invalid TLS certificates but accepts them to facilitate development environments with self-signed certificates:

```
WARNING: Invalid TLS certificate detected. Set JACS_STRICT_TLS=true for production.
```

### Production Configuration

For production deployments, enable strict TLS validation:

```bash
export JACS_STRICT_TLS=true
```

When enabled, JACS will:
- Reject connections with invalid, expired, or self-signed certificates
- Enforce proper certificate chain validation
- Fail fast with clear error messages for certificate issues

**Implementation**: Certificate validation logic is located in `jacs/src/schema/utils.rs`.

### Security Implications

| Mode | Behavior | Use Case |
|------|----------|----------|
| Default (dev) | Warn on invalid certs, allow connection | Local development, testing |
| Strict (`JACS_STRICT_TLS=true`) | Reject invalid certs | Production, staging |

## Signature Timestamp Validation

JACS signatures include timestamps to prevent replay attacks and ensure temporal integrity.

### How It Works

1. **Timestamp Inclusion**: Every signature includes a UTC timestamp recording when it was created
2. **Future Timestamp Rejection**: Signatures with timestamps more than 5 minutes in the future are rejected
3. **Optional Signature Expiration**: Configurable via `JACS_MAX_SIGNATURE_AGE_SECONDS` (disabled by default since JACS documents are designed to be eternal)
4. **Validation**: Timestamp validation occurs during signature verification

### Configuring Signature Expiration

By default, signatures do not expire. JACS documents are designed to be idempotent and eternal. For use cases that require expiration:

```bash
# Enable expiration (e.g., 90 days)
export JACS_MAX_SIGNATURE_AGE_SECONDS=7776000

# Default: no expiration (0)
export JACS_MAX_SIGNATURE_AGE_SECONDS=0
```

### Protection Against Replay Attacks

The 5-minute future tolerance window:
- Allows for reasonable clock skew between systems
- Prevents attackers from creating signatures with future timestamps
- Ensures signatures cannot be pre-generated for later fraudulent use

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "signature": "...",
    "date": "2024-01-15T10:30:00Z"  // Must be within 5 min of verifier's clock
  }
}
```

### Clock Synchronization

For reliable timestamp validation across distributed systems:
- Ensure all agents use NTP or similar time synchronization
- Monitor for clock drift in production environments
- Consider the 5-minute tolerance when debugging verification failures

## Verification Claims

Agents can claim a verification level that determines security requirements. This follows the principle: **"If you claim it, you must prove it."**

### Claim Levels

| Claim | Required Conditions | Behavior |
|-------|---------------------|----------|
| `unverified` (default) | None | Relaxed DNS/TLS settings allowed; self-asserted identity |
| `verified` | Domain with DNSSEC | Strict TLS, strict DNS with DNSSEC validation required |
| `verified-hai.ai` | Above + HAI.ai registration | Must be registered and verified with HAI.ai |

### Setting a Verification Claim

Add the `jacsVerificationClaim` field to your agent definition:

```json
{
  "jacsAgentType": "ai",
  "jacsVerificationClaim": "verified",
  "jacsAgentDomain": "myagent.example.com",
  "jacsServices": [...]
}
```

### Claim Enforcement

When an agent claims `verified` or `verified-hai.ai`:

1. **Domain Required**: The `jacsAgentDomain` field must be set
2. **Strict DNS**: DNS lookup uses DNSSEC validation (no insecure fallback)
3. **DNS Required**: Public key fingerprint must match DNS TXT record
4. **Strict TLS**: TLS certificate validation is mandatory (no self-signed certs)

For `verified-hai.ai` claims, additional enforcement:

5. **HAI.ai Registration**: Agent must be registered at [hai.ai](https://hai.ai)
6. **Public Key Match**: Registered public key must match the agent's key
7. **Network Required**: Verification fails if HAI.ai API is unreachable

### Backward Compatibility

- Agents without `jacsVerificationClaim` are treated as `unverified`
- Existing agents continue to work with their current DNS settings
- No breaking changes for agents that don't opt into verified status

### Error Messages

If verification fails, clear error messages explain what's wrong:

```
Verification claim 'verified' failed: Verified agents must have jacsAgentDomain set.
Agents claiming 'verified' must meet the required security conditions.
```

```
Verification claim 'verified-hai.ai' failed: Agent 'uuid' is not registered with HAI.ai.
Agents claiming 'verified-hai.ai' must be registered at https://hai.ai
```

### Security Considerations

1. **No Downgrade**: Once an agent claims `verified`, it cannot be verified with relaxed settings
2. **Claim Changes**: Changing the claim requires creating a new agent version
3. **Network Dependency**: `verified-hai.ai` requires network access to HAI.ai
4. **Audit Trail**: Verification claim and enforcement results are logged

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

## Trust Store Management

JACS maintains a trust store for managing trusted agent relationships.

### Trusting Agents

Before trusting an agent, JACS performs public key hash verification:

```python
# Trust an agent after verifying their public key hash
agent.trust_agent(agent_id, public_key_hash)
```

### Untrusting Agents

The `untrust_agent()` method properly handles the case when an agent is not in the trust store:

```python
try:
    agent.untrust_agent(agent_id)
except AgentNotTrusted as e:
    # Agent was not in the trust store
    print(f"Agent {agent_id} was not trusted: {e}")
```

### Trust Store Security

| Operation | Validation |
|-----------|------------|
| `trust_agent()` | UUID format validation, path traversal rejection, public key hash verification, self-signature verification before adding |
| `untrust_agent()` | UUID format validation, path containment check, returns `AgentNotTrusted` error if agent not found |
| `get_trusted_agent()` | UUID format validation, path containment check |
| `is_trusted()` | UUID format validation, safe lookup without side effects |
| Key cache (`load_public_key_from_cache`) | `require_relative_path_safe()` rejects traversal in `publicKeyHash` |
| Key cache (`save_public_key_to_cache`) | `require_relative_path_safe()` rejects traversal in `publicKeyHash` |

**Path Traversal Protection (v0.6.0)**: All trust store operations that construct file paths from agent IDs or key hashes use defense-in-depth:
1. **UUID format validation**: Agent IDs must match `UUID:UUID` format (rejects special characters)
2. **Path character rejection**: Explicit rejection of `..`, `/`, `\`, and null bytes
3. **Path containment check**: For existing files, canonicalized paths are verified to stay within the trust store directory
4. **`require_relative_path_safe()`**: Key hashes are validated to prevent traversal before constructing cache file paths

### Best Practices

1. **Verify Before Trust**: Always verify an agent's public key hash through an out-of-band channel before trusting
2. **Audit Trust Changes**: Log all trust store modifications for security auditing
3. **Periodic Review**: Regularly review and prune the trust store

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
  "jacs_enable_filesystem_quarantine": "true"
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
- [ ] Use environment variables for secrets (never store `jacs_private_key_password` in config)
- [ ] Enable DNS verification
- [ ] Configure strict security mode
- [ ] Enable audit logging
- [ ] Use TLS for all network transport
- [ ] Restrict key file permissions (0600 for keys, 0700 for key directory)
- [ ] Implement key rotation policy
- [ ] Set `JACS_STRICT_TLS=true` for certificate validation
- [ ] Use strong passwords (28+ bit entropy, 35+ for single character class)
- [ ] Enable signature timestamp validation
- [ ] Verify public key hashes before trusting agents
- [ ] Run `cargo audit` / `npm audit` / `pip audit` regularly for dependency vulnerabilities

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

## Troubleshooting Verification Claims

### Common Issues and Solutions

#### "Verified agents must have jacsAgentDomain set"

**Problem**: You set `jacsVerificationClaim` to `verified` but didn't specify a domain.

**Solution**: Either add a domain or use unverified:

```json
// Option 1: Add a domain (recommended for production)
{
  "jacsVerificationClaim": "verified",
  "jacsAgentDomain": "myagent.example.com"
}

// Option 2: Use unverified if DNS verification isn't needed
{
  "jacsVerificationClaim": "unverified"
}
```

#### "Agent is not registered with HAI.ai"

**Problem**: You're using `verified-hai.ai` but the agent isn't registered.

**Solution**:
1. Register your agent at [hai.ai](https://hai.ai)
2. Or use `verified` for DNS-only verification:

```json
{
  "jacsVerificationClaim": "verified",
  "jacsAgentDomain": "myagent.example.com"
}
```

#### "Cannot downgrade from 'verified' to 'unverified'"

**Problem**: You're trying to change an existing agent's claim to a lower level.

**Solution**: Verification claims cannot be downgraded for security. Options:
1. Keep the current claim level
2. Create a new agent with the desired claim level
3. If this is a test/development scenario, start fresh

```bash
# Create a new agent instead
jacs create --type ai --claim unverified
```

#### "DNS fingerprint mismatch"

**Problem**: The public key hash in DNS doesn't match your agent's key.

**Solution**:
1. Regenerate the DNS record with your current keys:
   ```bash
   jacs dns-record
   ```
2. Update your DNS TXT record with the new value
3. Wait for DNS propagation (can take up to 48 hours)

#### "Strict DNSSEC validation failed"

**Problem**: Your domain doesn't have DNSSEC enabled.

**Solution**:
1. Enable DNSSEC with your domain registrar
2. Publish DS records at the parent zone
3. Or use `verified` with non-strict DNS (development only)

### Claim Level Reference

| Claim | Security Level | Requirements |
|-------|----------------|--------------|
| `unverified` | 0 (lowest) | None - self-asserted identity |
| `verified` | 1 | Domain + DNS TXT record + DNSSEC |
| `verified-hai.ai` | 2 (highest) | Above + HAI.ai registration |

### Upgrade vs Downgrade Rules

- **Upgrades allowed**: `unverified` → `verified` → `verified-hai.ai`
- **Downgrades blocked**: Cannot go from higher to lower claim
- **Same level allowed**: Can update agent while keeping same claim

### Quick Diagnostic Commands

```bash
# Check your agent's current claim
jacs info | grep jacsVerificationClaim

# Verify DNS record is correct
jacs dns-check

# Test verification
jacs verify --agent your-agent-id:version
```

## See Also

- [Cryptographic Algorithms](crypto.md) - Algorithm details
- [DNS Verification](../dns.md) - DNS-based identity
- [Configuration](../schemas/configuration.md) - Security configuration
- [Agreements](../rust/agreements.md) - Multi-party agreements
