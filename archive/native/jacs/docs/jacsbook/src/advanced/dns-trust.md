# DNS Trust Anchoring

DNS can associate a public-key fingerprint with a domain. It does not by itself
prove the identity of a person or organization, authorize an action, or enroll
an agent in your trust store. The current native resolver's
[configuration and verifier coverage](https://github.com/HumanAssisted/JACS/blob/main/docs/key-discovery.md)
are distinct from portable CLI/MCP explicit-key verification and A2A card policy.

## Fingerprints and routing

Records at `_v1.agent.jacs.<domain>` use:

```text
v=jacs; jacs_agent_id=<agent-uuid>; alg=SHA-256; enc=base64; jac_public_key_hash=<raw-key-digest>
```

`jac_public_key_hash` encodes SHA-256 of raw public-key bytes. It is not the
signed envelope's historical `publicKeyHash` string or a hash of its PEM armor.
An optional HTTPS `uri` points to supported discovery JSON; otherwise the
resolver uses `https://<domain>/.well-known/jacs-pubkey.json`.

A signed v2 `agentDomain` is authenticated only after the envelope verifies.
Before then it is a routing hint. Network requests require explicit capability
opt-in, bounded secure transport and key/reference checks. Existing identity
conflicts or distrust are not overridden by discovering a new key.

## DNSSEC and local trust

Strict lookup requires the validating resolver to return a `Secure` DNSSEC
proof. A remote server's AD bit is not accepted as proof on its own. The zone
must be signed and its DS delegation correctly published. Non-strict lookup
has no equivalent cryptographic DNS authentication.

DNSSEC protects records in transit; it does not prevent a compromised or
authorized DNS administrator from publishing a new key. Short TTLs do not fix
that threat. Keep application identity pins, authorization and revocation
policy separate from discovery. HTTPS and DNSSEC support also do not make the
entire channel post-quantum secure.

## Rotation limits

Agent-specific lookup selects the relevant agent's records and matches a
candidate's raw digest. Multiple agents and overlapping keys can coexist;
conflicting locations for the same agent and fingerprint are rejected.
Publishing an old key does not certify that it remains authorized. JACS does
not automatically publish DNS changes, maintain a transparency history, or
provide a DNS revocation feed. Plan overlap around actual caches and retained
signed documents, and retain exact historical-version key endpoints as needed.

See [DNS publication](../rust/dns.md), [key rotation](key-rotation.md), and the
[current key-discovery guide](https://github.com/HumanAssisted/JACS/blob/main/docs/key-discovery.md).
