# Security Design Notes

This page is intentionally brief. The canonical security documentation is:

- [Security Model](../advanced/security.md)
- [DNS Trust Anchoring](../advanced/dns-trust.md)
- [Failure Modes](../advanced/failure-modes.md)

## Scope

JACS provides cryptographic integrity, signer attribution, and versioned provenance for documents and messages. It does not, by itself, establish real-world identity ownership; trust comes from key distribution and policy (local trust store, DNS, HAI, org controls).

## Design Invariants

1. Untrusted path inputs are validated before filesystem operations.
2. Private key material is protected in memory and encrypted at rest when password-based key encryption is enabled.
3. Signing records signer metadata, signing algorithm, and public key fingerprint (`publicKeyHash`) inside `jacsSignature`.
4. Verification is hash + signature + key resolution policy, not signature-only.

For implementation-level details and security controls, use the Security Model page above.
