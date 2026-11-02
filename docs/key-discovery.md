# Key discovery and verification

This guide describes the **current native source**, not a capability guaranteed
by published 0.15.0 packages. The portable CLI and MCP remain local cryptographic
interfaces. See [release status](release-status.md) and the
[DID/A2A identity guide](identity-standards.md) for the separate integration surfaces.

Finding a public key is not enrolling an identity. A successful signature check
proves possession of that key for the signed bytes. Applications still decide
which identity, version and key they trust, enforce revocation, and authorize
the requested action. A document's domain or a remote key-service response does
not override an existing trust-store conflict or distrust decision.

## Keep the three hash contracts separate

| Value | What is hashed | Use |
| --- | --- | --- |
| DNS `jac_public_key_hash` | SHA-256 of decoded raw public-key bytes | Pin the fetched key to the selected DNS record; canonical padded standard Base64 or 64 hexadecimal characters |
| Signed `jacsSignature.publicKeyHash` | The existing envelope profile's key reference | Preserve historical native references; v2 verification also recognizes the portable raw-key reference |
| Remote response `public_key_hash` | For `sha256:<hex>`, the exact returned `public_key` string bytes; for an expanded response's bare hash, raw key bytes; for the historical minimal response's bare hash, the native key alias | Validate the response's declared representation separately from the signed document reference |

Do not rewrite old envelopes, compare Base64 text with hexadecimal text, hash a
PEM wrapper as if it were a raw key, or simply strip `sha256:` and accept the
result. The resolver decodes the key, checks its algorithm and shape, recomputes
the relevant references, then the verifier checks the complete document signature.
The native discovery document's `publicKeyHash` remains its compatibility alias;
it is not the DNS fingerprint. JWK thumbprints are another distinct format.
Expanded key-service responses include `jacs_id`, `version`, `public_key_b64`
and `public_key_raw_b64`: their exact representation and decoded raw bytes
must agree. The response shape selects the checksum contract; the verifier
does not try alternate hash definitions until one passes. A reported revoked
key is rejected, although this is not a general revocation-feed implementation.

## Opt in to native discovery

Network access is disabled by default, even though the default source order is
`local,registry`. To require local resolution explicitly:

```sh
export JACS_KEY_RESOLUTION=local
```

For DNS followed by HTTPS key retrieval:

```sh
export JACS_KEY_RESOLUTION=local,dns
export JACS_ALLOW_DNS=true
export JACS_ALLOW_REMOTE_KEY_FETCH=true
export JACS_DNS_KEY_DOMAINS=agent.example.com
```

`JACS_DNS_KEY_DOMAINS` is a comma-separated list of bare DNS hostnames. A native
v2 envelope can also carry `jacsSignature.agentDomain`, added before signing
when the signer has an eligible configured domain. The producer normalizes an
HTTPS service origin to its bare DNS hostname without changing the stored
origin. It omits this optional hint for valid HTTP origins and local development
hosts (IP addresses, single-label names, `localhost` and `.local` names), so
existing local signing still works. Credentials, non-root paths, queries,
fragments and whitespace in a configured origin are rejected. Incoming signed
hints must already be bare DNS hostnames. The hint remains untrusted until
signature verification succeeds. Older metadata is not promoted into a
signed domain claim; portable producers do not automatically add this field.

For an explicitly chosen key service:

```sh
export JACS_KEY_RESOLUTION=local,registry
export JACS_ALLOW_REMOTE_KEY_FETCH=true
export JACS_KEYS_BASE_URL=https://keys.example.com
```

The registry source requests
`/jacs/v1/agents/<agentID>/keys/<agentVersion>` under that base URL, using the
UUIDs in the signed envelope. It does not request `latest` or guess a version.
If no base URL is configured, the existing default is `https://hai.ai`; this
guide and the local tests do not establish compatibility with a live service.
`JACS_REGISTRY_URL` / `JACS_ALLOW_REGISTRY` belong to the separate registry
verification-claim API, not this public-key fetch configuration.

`JACS_ALLOW_NETWORK=true` enables every network capability; prefer the narrower
permissions above. Opt-in permits requests, not acceptance of a key. Transport
policy validates HTTPS destinations and redirects, rejects private/reserved
addresses, pins validated DNS answers and bounds response sizes. An explicitly
configured exact loopback key-service URL is supported for testing; DNS TXT
URIs receive no loopback exception.

## Publish a DNS fingerprint and key document

At `_v1.agent.jacs.agent.example.com`, publish a record such as:

```text
v=jacs; jacs_agent_id=<agent-uuid>; alg=SHA-256; enc=hex; jac_public_key_hash=<64-hex-raw-key-digest>; uri=https://keys.example.com/jacs/v1/agents/<agent-uuid>/keys/<version-uuid>
```

Placeholders must be replaced. `uri` is optional and must be HTTPS without
credentials or a fragment. The resolver additionally rejects queries and
collection/`latest` endpoints. A URI must use the publisher's origin, or the
origin explicitly configured in `JACS_KEYS_BASE_URL` with the exact
`/jacs/v1/agents/<agentID>/keys/<agentVersion>` path. Thus the cross-origin
example above requires `JACS_KEYS_BASE_URL=https://keys.example.com`.
Without a URI, discovery fetches
`https://agent.example.com/.well-known/jacs-pubkey.json`. It does not guess an
unserved PEM path or automatically fall back to an arbitrary JWKS. The native
export supplies `agentId`, `agentVersion`, `algorithm`, `publicKey` and
`publicKeyHash`; the identity/version and signed reference must match the
requested document. A custom URI must return the supported native discovery
JSON or key-service JSON (`public_key`, `algorithm`, `public_key_hash`).
Keys may be standard Base64 raw bytes or a single `PUBLIC KEY` PEM block;
Ed25519, ML-DSA-87 and ES256 SPKI wrappers are decoded to their raw public keys.

Use `jacs-compat agent dns --domain agent.example.com --encoding hex` to generate
the configured identity's fingerprint record. The command prints publication
material; it does not modify DNS. The Rust
`dns::bootstrap::build_agent_dns_txt_with_uri` helper adds a validated URI.
Keep historical keys available at explicit version locations if old documents
must remain verifiable; a current-key-only well-known document is insufficient.

Records are selected by `jacs_agent_id` and the candidate's raw-key digest.
A domain can host multiple agents and overlapping old/new fingerprints.
Conflicting URIs for the same agent and fingerprint are rejected. Publishing
an old fingerprint does not mark it trusted or unrevoked. There is no built-in
revocation feed, automatic DNS publication, transparency history, or universal
rotation wait period. Plan overlap around actual caches and application policy.
If several records point to one URI, the returned candidate is compared with
the agent's complete eligible fingerprint set. An unavailable source can permit
another configured source to be tried in non-strict mode; malformed or
contradictory DNS discovery metadata never permits that downgrade. Generic
registry-source errors can try later configured sources; a reported revocation
is terminal. In strict mode every DNS
discovery failure is terminal, including an unavailable pinned HTTPS endpoint.

Strict DNS lookup requires a `Secure` DNSSEC proof from the validating resolver;
an asserted AD bit alone is insufficient. Enable zone signing and publish the
DS delegation before requiring it. Non-strict lookup lacks that authentication.
For native agent validation, `jacs-compat agent verify --require-strict-dns`
requires DNSSEC. Shared native key discovery is strict when the loaded agent
has `jacs_dns_strict: true` in its configuration or `Agent::set_dns_strict(true)`.
DNSSEC protects DNS data, not against an authorized domain administrator publishing
an unwanted key, and it does not establish an organization's identity by itself.

For a caller-selected key, native Rust exposes
`dns::bootstrap::verify_agent_dns_with_key(agent_json, domain, key, algorithm, require_secure)`.
It verifies v2 document integrity and the raw-key DNS fingerprint separately;
legacy v1 signatures are not accepted by this integrity API. `verified` means
those checks passed, not independent identity authorization or DNSSEC unless
`require_secure` was selected. The convenience `verify_agent_dns` first resolves
a key for the supplied domain and exact signed version.

## Which verifiers use it?

| Surface | Discovery boundary |
| --- | --- |
| Native JSON envelopes, standalone verification and document service | Resolve the exact signed identity/version/key reference through the shared native resolver |
| Native text/image v2 envelopes and MIME dispatch | Use their full signed envelope for resolution; legacy compact blocks without an immutable version stay local |
| Native A2A wrapped artifact provenance and full attestation verification | Resolve the JACS envelope key; protocol-specific claims still need their own validation |
| Native `verify_attestation_local` | Stays offline; does not enable discovery even when network permissions are set |
| Frozen `jacs-response-v2` response signatures | Retain their explicit/current-key path; their format lacks an immutable `agentVersion`, so no historical or `latest` lookup is invented |
| Native explicit `verify_with_key` | Uses the supplied key; no automatic discovery |
| Legacy A2A Agent Card policy | Separate same-origin JWKS/TOFU or strict trust policy; not the envelope resolver |
| Typed A2A 1.0 `verify_root_card` | Caller supplies the expected root, identity and version; no network discovery |
| DID request proofs | Caller supplies the DID document and verification context; no general DID resolver |
| VC/Data Integrity/AP2 compatibility exports | No universal incoming verifier or automatic DNS/key-service resolution |
| Portable `jacs verify` | Caller supplies local `--agent` or `--public-identity` material |
| Portable MCP `jacs_verify_document` | Caller supplies canonical standard-Base64 raw `public_key` and `algorithm` |

Language bindings use these behaviors only through the native verification
entry points they expose. An endpoint serving DID, JWKS or Agent Card documents
does not automatically implement every verifier in this table. Verify the exact
format, trusted identity and authorization policy at each integration boundary.
