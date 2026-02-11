# DNS Trust Anchoring

JACS uses DNS TXT records to anchor agent identity to domain names, providing a decentralized trust layer that does not require a central certificate authority. This page explains the trust model, configuration levels, and known limitations.

## How It Works

When an agent has `jacsAgentDomain` set, JACS publishes a TXT record at `_v1.agent.jacs.<domain>` containing a fingerprint of the agent's public key. During verification, JACS resolves this record and compares the fingerprint against the agent's actual key material.

The TXT record format:

```
v=hai.ai; id=<agent-uuid>; alg=sha256; enc=base64; fp=<digest>
```

If the digest matches the local public key hash, the agent's identity is confirmed through DNS.

## Four Configuration Levels

| `dns_validate` | `dns_required` | `dns_strict` | CLI Flag | Behavior |
|---|---|---|---|---|
| false | false | false | `--ignore-dns` | No DNS checks at all. Verification relies only on embedded fingerprints. |
| true | false | false | `--no-dns` | Attempt DNS lookup; fall back to embedded fingerprint on failure. |
| true | true | false | `--require-dns` | DNS TXT record must exist and match. No fallback to embedded fingerprint. |
| true | true | true | `--require-strict-dns` | DNS TXT record must exist, match, and be DNSSEC-authenticated. |

**Default behavior**: When no flags are set, `dns_validate` and `dns_required` are derived from whether `jacsAgentDomain` is present in the agent document. If a domain is set, validation and requirement default to `true`. `dns_strict` always defaults to `false`.

**Verified claims override**: Agents with `jacsVerificationClaim` set to a verified level automatically use `validate=true, strict=true, required=true` regardless of flags.

## Security Model Assumptions

1. **Domain ownership implies identity**: The entity controlling DNS for a domain is authorized to speak for agents on that domain.
2. **TXT records are tamper-evident with DNSSEC**: When `--require-strict-dns` is used, the full DNSSEC chain of trust (root -> TLD -> domain -> record) provides cryptographic integrity.
3. **Embedded fingerprints are a weaker fallback**: Without DNS, JACS trusts the `jacsPublicKeyHash` field embedded in the agent document. This proves key consistency but not domain ownership.

## Known Attack Vectors

| Attack | Risk Level | Mitigated By |
|---|---|---|
| **DNS cache poisoning** | Medium | DNSSEC (`--require-strict-dns`), short TTLs |
| **TXT record manipulation** (compromised DNS credentials) | High | DNSSEC, monitoring, key rotation |
| **DNS spoofing** (man-in-the-middle) | Medium | DNSSEC validation, DNS-over-HTTPS resolvers |
| **Stale records after key rotation** | Low | TTL management, re-publishing records before rotation |
| **Downgrade to embedded-only** | Medium | Use `--require-dns` to prevent fallback |

## What JACS Provides

- **Fingerprint binding**: The TXT record ties a specific public key to a domain, preventing key substitution.
- **Multiple verification levels**: From no-DNS (local development) to strict DNSSEC (production cross-org).
- **Fallback logic**: When DNS is unavailable and not required, verification degrades gracefully to embedded fingerprint comparison.
- **Error specificity**: Distinct error messages for "record missing," "fingerprint mismatch," "DNSSEC failed," and "agent ID mismatch."

## What JACS Does Not Yet Provide

- **Active DNSSEC chain validation**: JACS relies on the system resolver (or DoH) for DNSSEC; it does not perform independent DNSKEY/DS chain validation.
- **Certificate Transparency-style monitoring**: No log of historical TXT record changes. Domain owners must monitor independently.
- **Automatic key-to-DNS synchronization**: Publishing and updating TXT records is a manual step (or CI/CD-driven).

## Recommendations

| Environment | Minimum Setting | Reason |
|---|---|---|
| Local development | `--ignore-dns` or `--no-dns` | No real domain needed |
| Internal org | `--no-dns` | DNS available but not critical |
| Cross-org production | `--require-dns` | Prevents impersonation across trust boundaries |
| High-security / regulated | `--require-strict-dns` | Full DNSSEC chain required |

For production cross-organization deployments, use `--require-dns` at minimum. Enable DNSSEC on your domain and use `--require-strict-dns` when the infrastructure supports it.

## See Also

- [DNS-Based Verification](../rust/dns.md) -- setup guide with provider-specific instructions
- [Security Model](security.md) -- broader security architecture
- [Key Rotation](key-rotation.md) -- coordinating key changes with DNS updates
