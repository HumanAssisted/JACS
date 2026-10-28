# DNS-Based Agent Verification

Native JACS can publish a raw public-key fingerprint in DNS and retrieve a
candidate key over HTTPS. Discovery is opt-in and does not enroll a trusted
identity. Start with the [key discovery and verification guide](https://github.com/HumanAssisted/JACS/blob/main/docs/key-discovery.md)
for the current source's configuration, exact-version lookup and verifier coverage.
Portable `jacs` CLI/MCP verification continues to require explicit key material.

## Generate publication material

With an existing native identity configured in `jacs.config.json`:

```sh
jacs-compat agent dns --domain agent.example.com --encoding hex
jacs-compat agent dns --domain agent.example.com --provider aws
jacs-compat agent dns --domain agent.example.com --provider azure
jacs-compat agent dns --domain agent.example.com --provider cloudflare
```

These commands print records or provider-specific publication material. Review
and publish it through your DNS operator; the CLI does not change DNS itself.
`--ttl` selects the record TTL. The default digest encoding is standard Base64;
`--encoding hex` selects hexadecimal. Both encode SHA-256 of the raw public key.

The record at `_v1.agent.jacs.agent.example.com` has this shape:

```text
v=jacs; jacs_agent_id=<agent-uuid>; alg=SHA-256; enc=hex; jac_public_key_hash=<64-hex-raw-key-digest>
```

An optional `uri=https://...` identifies supported key-discovery JSON on the
publisher origin or an explicitly configured registry's exact-version endpoint. Without
it, the native resolver requests the domain's `/.well-known/jacs-pubkey.json`.
The Rust `build_agent_dns_txt_with_uri` helper validates this field. Publish
only public material. A served current-key document cannot substitute for the
exact historical version named by an older signature.

## Configure verification

```sh
export JACS_KEY_RESOLUTION=local,dns
export JACS_ALLOW_DNS=true
export JACS_ALLOW_REMOTE_KEY_FETCH=true
export JACS_DNS_KEY_DOMAINS=agent.example.com
```

A native v2 envelope may also contain a signed `agentDomain` routing hint.
Until the complete signature verifies, treat that field as untrusted input.
The fetched key must match the DNS fingerprint, signed key reference,
algorithm and identity/version. A domain claim alone is not a trusted identity.

For the configured native agent's own validation:

```sh
JACS_ALLOW_DNS=true jacs-compat agent verify --require-strict-dns
```

Strict mode requires an actual `Secure` DNSSEC proof; an AD flag by itself does
not establish it. Configure zone signing and the registrar's DS delegation
first. Do not silently weaken strict policy to make a failed check pass.
The [DNS trust guide](../advanced/dns-trust.md) explains the remaining boundaries.

## Rotation and troubleshooting

Agent-specific lookup accepts multiple agents and overlapping fingerprints in
the same TXT record set. It rejects conflicting URIs for one agent/fingerprint.
Retain historical key endpoints where your application needs old documents,
and enforce revocation independently. TTLs, caches and retention policy govern
your overlap; there is no fixed universal wait period.

Use `dig +dnssec _v1.agent.jacs.agent.example.com TXT` to inspect records;
requesting DNSSEC records with `dig` alone does not prove validation succeeded.
On a mismatch, check the decoded raw key and selected agent/version rather than
comparing the encoded DNS digest to `jacsSignature.publicKeyHash`. Their
[hash contracts differ](https://github.com/HumanAssisted/JACS/blob/main/docs/key-discovery.md#keep-the-three-hash-contracts-separate).
