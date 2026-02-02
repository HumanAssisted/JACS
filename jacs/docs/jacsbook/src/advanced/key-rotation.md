# Key Rotation

Key rotation is the process of replacing an agent's cryptographic keys while preserving the ability to verify documents signed with previous keys. JACS implements version-aware key management to support secure key lifecycle operations.

## Why Key Rotation Matters

### Key Compromise Recovery

When a private key is compromised, the agent must be able to:
- Generate new keys and continue operating
- Revoke trust in the compromised key
- Maintain verifiability of documents signed before the compromise

### Cryptographic Agility

Cryptographic algorithms evolve. Key rotation enables:
- Migration from older algorithms to newer ones
- Transition to post-quantum cryptography when needed
- Algorithm upgrades without breaking existing signatures

### Compliance Requirements

Many security standards require periodic key rotation:
- PCI-DSS mandates regular key changes
- SOC 2 requires key management policies
- NIST guidelines recommend rotation schedules

## Agent Versioning

JACS uses a versioned identity model where each key rotation creates a new agent version.

### Version Format

Agent identifiers follow the format: `{agent_id}:{version_uuid}`

- **jacsId**: The stable agent identity (UUID v4) - never changes
- **jacsVersion**: Current version UUID - changes on each update
- **jacsPreviousVersion**: Links to the prior version
- **jacsOriginalVersion**: The first version ever created

```json
{
  "jacsId": "550e8400-e29b-41d4-a716-446655440000",
  "jacsVersion": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "jacsPreviousVersion": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "jacsOriginalVersion": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
}
```

### Version Chain

Each version forms a linked chain back to the original:

```
Original (v1) <-- Previous (v2) <-- Current (v3)
   |                 |                  |
 key-A             key-B              key-C
```

This chain provides an audit trail of all key changes and allows verification of any version.

## Version-Aware Verification

The critical insight enabling key rotation is that signatures contain both the agent ID and the version that created them.

### Signature Structure

```json
{
  "jacsSignature": {
    "agentID": "550e8400-e29b-41d4-a716-446655440000",
    "agentVersion": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "publicKeyHash": "sha256-of-public-key-A",
    "signingAlgorithm": "ring-Ed25519",
    "signature": "base64-encoded-signature",
    "date": "2024-01-15T10:00:00Z"
  }
}
```

### Key Resolution Process

When verifying a signature:

1. Extract `agentVersion` and `publicKeyHash` from the signature
2. Look up the public key that was active for that version
3. Verify the signature using that historical key

```rust
// Pseudocode for version-aware verification
fn verify_signature(doc: &Document) -> Result<()> {
    let sig = &doc.jacs_signature;

    // Find the key that was active for this version
    let public_key = resolve_key_for_version(
        &sig.agent_id,
        &sig.agent_version,
        &sig.public_key_hash,
    )?;

    // Verify with the historical key
    verify_with_key(&doc, &sig, &public_key)
}
```

### Key Lookup Priority

The verification system tries multiple sources:

1. **Local cache by hash** - Fastest, key already stored locally
2. **Trust store by version** - Most accurate for known agents
3. **Trust store by hash** - Fallback for legacy entries
4. **DNS lookup** - External verification, authoritative
5. **Fail** - Key not found, verification impossible

## Key Rotation Process

### Step-by-Step Rotation

1. **Generate new key pair** with the desired algorithm
2. **Create new agent version** with updated key information
3. **Sign new version with old key** (transition signature)
4. **Update DNS records** to include new key fingerprint
5. **Store old public key** for future verifications

### Transition Signature

The transition signature proves the key rotation was authorized by the holder of the old key:

```
JACS_KEY_ROTATION:{agent_id}:{old_key_hash}:{new_key_hash}:{timestamp}
```

This signed message:
- Proves continuity of ownership
- Provides an audit trail
- Binds old and new keys together cryptographically

### CLI Commands (Planned)

> **Note**: These CLI commands are planned for a future release. Currently, key rotation must be performed programmatically using the Rust API.

```bash
# Rotate keys with default algorithm (Coming Soon)
jacs agent rotate-keys

# Rotate to post-quantum algorithm (Coming Soon)
jacs agent rotate-keys --algorithm pq2025

# List key history (Coming Soon)
jacs agent keys list

# Revoke a compromised key (Coming Soon)
jacs agent keys revoke <key-hash>
```

### Example Rotation Flow

```
Time T0: Agent created
  - jacsId: "abc-123"
  - jacsVersion: "v1-uuid"
  - jacsCurrentKeyHash: "hash-A"

Time T1: Agent signs document D1
  - D1.jacsSignature.agentVersion: "v1-uuid"
  - D1.jacsSignature.publicKeyHash: "hash-A"

Time T2: Key rotation
  - New keys generated with hash-B
  - jacsVersion: "v2-uuid"
  - jacsKeyHistory: [{ hash: "hash-A", status: "rotated" }]
  - jacsCurrentKeyHash: "hash-B"

Time T3: Verify D1
  - Extract agentVersion "v1-uuid" and hash "hash-A"
  - Look up key: find "hash-A" with status "rotated"
  - Verification succeeds (old key still valid for old docs)

Time T4: Agent signs document D2
  - D2.jacsSignature.agentVersion: "v2-uuid"
  - D2.jacsSignature.publicKeyHash: "hash-B"
```

## Trust Store with Version History

The trust store maintains a history of all public keys for each trusted agent.

### TrustedAgent Structure

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Example Agent",
  "trusted_at": "2024-01-15T10:00:00Z",
  "current_key_hash": "abc123...",
  "domain": "agent.example.com",
  "key_history": [
    {
      "public_key_hash": "xyz789...",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
      "signing_algorithm": "ring-Ed25519",
      "trusted_at": "2024-01-01T00:00:00Z",
      "first_version": "11111111-1111-1111-1111-111111111111",
      "last_version": "22222222-2222-2222-2222-222222222222",
      "status": "rotated"
    },
    {
      "public_key_hash": "abc123...",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
      "signing_algorithm": "ring-Ed25519",
      "trusted_at": "2024-01-15T10:00:00Z",
      "first_version": "33333333-3333-3333-3333-333333333333",
      "last_version": null,
      "status": "active"
    }
  ]
}
```

### Key Status Values

| Status | Description |
|--------|-------------|
| `active` | Currently in use for signing |
| `rotated` | Superseded by newer key, still valid for old signatures |
| `revoked` | Compromised, signatures should not be trusted |
| `expired` | Past validity period |

### Looking Up Keys

```rust
impl TrustedAgent {
    /// Get the public key that was active for a specific agent version
    fn get_key_for_version(&self, version: &str) -> Option<&KeyEntry> {
        self.key_history.iter().find(|entry| {
            match (&entry.first_version, &entry.last_version) {
                (Some(first), Some(last)) => {
                    version >= first && version <= last
                }
                (Some(first), None) => {
                    version >= first  // Current key
                }
                _ => false
            }
        })
    }

    /// Get the public key by its hash
    fn get_key_by_hash(&self, hash: &str) -> Option<&KeyEntry> {
        self.key_history.iter().find(|e| e.public_key_hash == hash)
    }
}
```

## DNS Support for Key Versions

DNS records can advertise multiple key versions for an agent.

### Multi-Version DNS Records

Each key version gets its own TXT record:

```
; Current key
_v1.agent.jacs.example.com. 3600 IN TXT "v=hai.ai; jacs_agent_id={id}; ver=current; alg=SHA-256; hash={hash1}"

; Previous key (still valid for old signatures)
_v1.agent.jacs.example.com. 3600 IN TXT "v=hai.ai; jacs_agent_id={id}; ver=rotated; valid_until=2025-01-15; hash={hash2}"
```

### DNS Record Generation

```bash
# Generate DNS records for all active keys
jacs agent dns --all-keys
```

## Security Considerations

### Key Revocation

When a key is compromised:

1. **Mark as revoked** in the agent's key history
2. **Update DNS** to include revocation status
3. **Signatures fail verification** when made with revoked keys
4. **Notify trusted peers** if possible

### Overlap Period

During rotation, both old and new keys may be valid:

- New documents should be signed with the new key
- Old documents remain verifiable with the old key
- DNS may advertise both keys during transition

### Secure Deletion

After rotation:

- Old private keys should be securely deleted
- Only public keys are retained for verification
- Key metadata must be protected from modification

## Best Practices

### Rotation Schedule

- **Regular rotation**: Quarterly or annually for compliance
- **Algorithm upgrade**: When transitioning to stronger cryptography
- **Incident response**: Immediately after suspected compromise

### Pre-Rotation Checklist

- [ ] Backup current agent state
- [ ] Verify all systems can handle new key format
- [ ] Plan DNS propagation time
- [ ] Notify dependent systems of upcoming change

### Post-Rotation Checklist

- [ ] Verify new key is active
- [ ] Confirm old documents still verify
- [ ] Update DNS records
- [ ] Securely delete old private key
- [ ] Test signing with new key

## See Also

- [Security Model](security.md) - Overall security architecture
- [Cryptographic Algorithms](crypto.md) - Algorithm details
- [DNS Verification](../rust/dns.md) - DNS-based identity verification
