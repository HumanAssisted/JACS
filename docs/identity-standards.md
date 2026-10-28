# DID and post-quantum identity

Use the same persistent native JACS signing key for identity and discovery.
A `pq2025` identity holds a final-FIPS-204 ML-DSA-87 key; exporting a public
representation or restarting a service does not create another root key.
Rotation is a deliberate identity update. This page describes **this checkout**;
the [published 0.15.0 artifacts](release-status.md) do not establish availability
of these new exports in an installed package.

## Run the native integration

The portable `jacs mcp` server remains the primary tool integration. DID exports
and A2A discovery use the separate native Rust library and `jacs-compat` CLI.
To install that CLI from this checkout, run from the repository root:

```sh
cargo install --locked --path archive/native/jacs-cli
```

In a private working directory, create or load a persistent native identity:

```sh
jacs-compat quickstart --name example-agent --domain agent.example.com
jacs-compat w3c did --origin https://agent.example.com
jacs-compat w3c did-document --origin https://agent.example.com > did.json
jacs-compat w3c well-known --origin https://agent.example.com --out discovery
```

Provide the encryption password through the host's secret manager using
`JACS_PRIVATE_KEY_PASSWORD` or the native CLI's configured keychain. Keep
passwords out of command arguments and committed files. These commands use
`./jacs.config.json` by default (`JACS_CONFIG` selects another configuration).
Publish the generated public documents at the exact paths returned by the
export; the CLI export itself does not deploy them or establish domain control.

## Public formats and trust

| Surface | Current source behavior |
| --- | --- |
| Public JWK / JWKS | RFC 9964 `kty: "AKP"`, `alg: "ML-DSA-87"`, `pub: "<base64url raw key>"`; public material only |
| DID | `did:wba:<host>:agent:<jacsId>`; document at `/agent/<jacsId>/did.json`; `JsonWebKey` verification method with DID v1 and Controlled Identifiers v1 contexts |
| Legacy discovery | The native PQ root signs the existing `0.4.0` card with compact ML-DSA-87 JWS |
| Typed A2A 1.0 | `a2a::v1` signs its bounded card profile with detached ML-DSA-87 JWS using `signatures[].protected` and `signature`; see [A2A scope](../A2A_QUICKSTART.md) |
| ES256 compatibility | Explicit alternate signing path with a persisted compatibility key and native-root-signed, scoped binding |

`did:wba` is the implemented method. Generic `did:web` or `did:key` mappings
are architectural possibilities, not exports provided here. JACS does not
implement a general DID resolver. DID Core conformance does not establish
method-specific interoperability or a trusted relationship to a domain.

For ML-DSA-87, the JWK `kid` is the RFC 7638/RFC 9964 thumbprint;
repeated exports preserve it. The Ed25519 DID export retains its existing
verification-method URL and uses that URL's fragment as `kid`. Thumbprint
identifiers are a recommended CID practice, not a universal DID requirement.
JWS signs its exact protected-header/payload
signing input using pure ML-DSA and an empty context. JACS document envelopes
and JWS are different signed formats; their signature bytes are not interchangeable.
The JACS public AKP profile accepts only `kty`, `alg`, `pub`, `kid`, `use` and
`key_ops`; optional `use` must be `sig`, `key_ops` must be `["verify"]`, and
`kid` must match the thumbprint. This profile is stricter than general JOSE.

Check a received key against trusted identity evidence before accepting it.
Select the expected algorithm and relevant DID verification relationship,
apply current authorization and revocation policy, and reject unsupported
algorithms. [Key discovery and verification](key-discovery.md) explains native
DNS/HTTPS lookup, exact-version resolution and explicit-key portable boundaries.
A peer that lacks ML-DSA support needs a deliberately selected
compatibility integration; a PQ verification error never triggers a downgrade.

## Library entry points

The native Rust [`jacs::w3c`](../archive/native/jacs/src/w3c/mod.rs) module exposes
`export_did_identifier_with_options`, `export_did_document` and
`generate_w3c_well_known_documents`, using `W3cDidOptions { origin: ... }`.
The native [`jacs::a2a::simple`](../archive/native/jacs/src/a2a/simple.rs) helpers
accept an already loaded `SimpleAgent`:

```rust,ignore
let documents = jacs::a2a::simple::generate_well_known_documents(&agent, None)?;
// Explicit compatibility for a peer that requires ES256:
let compat = jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))?;
```

The default legacy discovery path requires the persisted `pq2025` identity. It publishes that
root's public JWK and signs with that root; it does not generate an ephemeral
Agent Card key. The explicit ES256 path retains its scoped compatibility
binding. Check individual [language bindings](libraries.md) before assuming
every Rust helper is exposed in Node.js, Python or Go.

For the typed **A2A 1.0** profile, use a loaded native `Agent` with
[`jacs::a2a::v1`](../archive/native/jacs/src/a2a/v1.rs):

```rust,ignore
let profile = jacs::a2a::v1::project_agent_card(&agent, "https://agent.example.com/a2a")?;
let signed_card = jacs::a2a::v1::export_agent_card(&mut agent, key_directory, profile)?;
jacs::a2a::v1::verify_root_card(
    &signed_card, &public_jwk, expected_id, expected_version, trusted_root,
)?;
```

Here `public_jwk` is the root's AKP JWK; `expected_id`, `expected_version` and
`trusted_root` come from independent trusted evidence. `verify_root_card`
checks the detached signature, supported card profile and exact root attribution.
It accepts multiple detached signatures, selecting the entry with the expected
root `kid` regardless of order. Duplicate `kid` values and invalid entry/header
shapes are rejected. Other signatures receive no authority and are not
cryptographically verified by this helper. It is stateless and does not
establish revocation or rollback history.
`key_directory` remains in the exporter signature for source compatibility;
the PQ path uses the loaded root and creates no compatibility key.

`v1::export_agent_card_es256` takes the same arguments for an explicitly
selected ES256 peer. The existing `v1::verify_card_binding` validates that
compatibility binding; callers must also verify its card JWS. The older
`project_agent_card` helper builds the finite report example's profile.
Application-facing discovery options require the caller's actual skills,
input/output modes and messaging URL; they do not invent a report skill.

## Node.js and Python v1 discovery

Both public language APIs now accept explicit A2A 1.0 discovery options. See
[copyable Node/Python examples](../A2A_QUICKSTART.md#a2a-10-from-nodejs-or-python).
Node's `buildWellKnownDocuments(client, options)` and middleware accept
`protocolVersion`, `messagingUrl`, `skills`, `defaultInputModes` and
`defaultOutputModes`. Python's
`client.get_a2a().generate_well_known_documents(discovery_options=options)` and
`create_a2a_app(..., discovery_options=options)` use the same JSON option names.
No options preserves legacy discovery. These functions export or serve public
discovery documents; the caller owns the messaging handler.

Native ML-DSA-87 is the default signing choice. Select Node's
`a2aAlgorithm: "ES256"` or Python's `a2a_algorithm="ES256"` explicitly only for
a peer needing compatibility. A classical-root CLI agent likewise requires
`jacs-compat a2a serve --a2a-algorithm ES256`; errors never silently downgrade.

[Current official SDK smokes](../archive/native/examples/a2a_v1_sdk/README.md)
use public JACS APIs, actual SDK servers/clients, and independent SDK signature
verification. The JavaScript SDK 1.3.0 works with direct ML-DSA-87 through
`jose` 6.2.13 on Node 24.7+ with ML-DSA WebCrypto. The Python SDK 1.3.0 uses
explicit ES256 because its PyJWT backend lacks ML-DSA verification. Maintained
JACS Python source requires Python 3.11+. The native root remains PQ in both
examples, and the Python path additionally verifies its scoped native binding.
These checks cover a finite JSON-RPC report exchange, not every A2A capability.

Stock SDK signature validation still needs trusted key selection. Resolve and
verify the card before selecting its transport or fetching an extended card.
The JS example pins the exported JWK to independently supplied root bytes, checks the
expected identity/version and protected algorithm, and rejects unexpected key
URLs. Official SDK canonicalization drops fields outside its A2A schema; do
not treat those fields as authenticated application claims. Fetching a card or
JWKS alone establishes none of that trust. Legacy
`verified`/`strict` discovery policy helpers are not v1 policy parsers. Legacy
PQ verification checks identity/version/root-key metadata consistency before
TOFU pinning. Its key fingerprint now hashes raw public-key bytes. A PQ TOFU
pin created by an earlier unpublished direct-PQ build may use the old lossy
fingerprint and will fail closed: independently verify the actual identity
and key before deliberately replacing that pin. There is no automatic pin
reset or migration; ES256 pins and explicit trusted-root checks are unchanged.

## Standards boundaries

[The checked standards note](research/pq-identity-standards.md) cites RFC 9964,
DID Core, Controlled Identifiers, the current W3C VC recommendations and A2A.
`JsonWebKey` with an AKP JWK is the public-key representation; it is not a
claim of a standardized ML-DSA-87 Data Integrity cryptosuite. Existing VC and
Data Integrity exports retain their explicit ES256 compatibility behavior.

The native `JacsW3cRequestProof` / `DIDWba` request-proof JSON is JACS-specific;
it is not ANP HTTP Message Signatures. Its verifier can infer ML-DSA-87 or
Ed25519 from a standard public JWK; an optional `jacsSigningAlgorithm` must
agree. DID document method IDs and `authentication` references may be absolute
local DID URLs or `#fragment` references, with matching controller and no
ambiguous IDs. The proof itself must name an absolute local DID URL. ES256
compatibility methods are not supported by this request-proof protocol.

A2A's current 1.0 specification also has
a different Agent Card wire shape from the legacy discovery model here. PQ
signatures alone do not make DID resolution, TLS, or an entire A2A deployment
post-quantum secure.
