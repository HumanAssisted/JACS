# A2A integration quickstart

A2A discovery and signed artifacts are available through the native integration
libraries and extended `jacs-compat` CLI. The portable `jacs mcp` server exposes
local cryptographic tools; it has no A2A transport or discovery tools.

## Try this checkout

Install the native CLI from the repository root:

```sh
cargo install --locked --path archive/native/jacs-cli
```

In a private working directory, configure `JACS_PRIVATE_KEY_PASSWORD` through
your secret manager or use the native CLI's configured keychain, then run:

```sh
jacs-compat a2a quickstart --name example-agent --domain agent.example.com
```

This creates or loads a persistent `pq2025` identity and serves its discovery
documents on `http://127.0.0.1:8080`. For an existing native identity:

```sh
jacs-compat a2a serve --host 127.0.0.1 --port 8080
```

For a production reverse proxy, pass the controlling HTTPS origin with
`--origin https://agent.example.com`. The listener's address and advertised
origin are distinct. This server hosts discovery documents, not a general
A2A task executor. Never expose an endpoint merely because it appears in a card.

In current source, default discovery signs with the same persisted ML-DSA-87
root key and publishes its RFC 9964 AKP JWK. No unrelated ephemeral key is
created on export or restart. The Rust helper
`jacs-compat a2a serve --a2a-algorithm ES256` selects the compatibility
path explicitly. `--algorithm` on quickstart selects the native identity
algorithm; `--a2a-algorithm` separately selects the card signing algorithm. See
[DID and post-quantum identity](docs/identity-standards.md) for key formats,
source APIs and trust boundaries.

## A2A 1.0 from Node.js or Python

Select `protocolVersion: "1.0"` explicitly and supply the actual messaging URL,
nonempty skills and input/output modes. JACS signs those declarations; your
application must implement the advertised interface. The default discovery
profile and the CLI discovery server remain the legacy `0.4.0` card format.

Node.js, using a loaded `JacsClient`:

```js
const { buildWellKnownDocuments } = require('@hai.ai/jacs/a2a-server');
const documents = buildWellKnownDocuments(client, {
  protocolVersion: '1.0',
  messagingUrl: 'https://agent.example.com/a2a',
  skills: [{ id: 'report', name: 'Report', description: 'Return a report', tags: ['report'] }],
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['application/json'],
});
```

Python, using a loaded `JacsClient`, with explicit compatibility for its current
official SDK signing backend:

```python
documents = client.get_a2a().generate_well_known_documents(
    a2a_algorithm="ES256",
    discovery_options={
        "protocolVersion": "1.0",
        "messagingUrl": "https://agent.example.com/a2a",
        "skills": [{"id": "report", "name": "Report", "description": "Return a report", "tags": ["report"]}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["application/json"],
    },
)
```

Omit `a2a_algorithm` to export a direct ML-DSA-87 card in Python; that does not
make its stock SDK verifier support the algorithm. Node's default above signs
with the native PQ root. Both v1 paths use the standard detached
`signatures[].protected` and `signature` fields. Legacy discovery retains compact
`signatures[].jws`. The native Rust [`a2a::v1`](archive/native/jacs/src/a2a/v1.rs)
module also exposes typed signing and root verification.

The [runnable official SDK examples](archive/native/examples/a2a_v1_sdk/README.md)
exercise actual discovery, signature verification and JSON-RPC report exchange:

| Peer | Card signature | Runtime |
| --- | --- | --- |
| `@a2a-js/sdk` 1.3.0 | ML-DSA-87 using the stock SDK and `jose` 6.2.3 | Node 24.7+ with ML-DSA WebCrypto |
| `a2a-sdk` 1.3.0 | Explicit ES256, with a PQ-root-signed compatibility binding | Python 3.11+ |

SDK version `1.3.0` and wire protocol version `1.0` are different numbers.
The Python SDK's PyJWT backend does not provide ML-DSA verification. Neither
example upgrades legacy discovery or implements every A2A capability. See the
[identity and trust guide](docs/identity-standards.md) and
[checked specification research](docs/research/pq-identity-standards.md).

## Release scope

Version 0.15.0 is [published](docs/release-status.md), but the new native PQ
DID/JWK/Agent Card behavior described above is a source change. Installing
`jacs==0.15.0`, `@hai.ai/jacs@0.15.0` or `jacs-cli-compat@0.15.0` does not
prove it contains these changes. Use [package guidance](docs/libraries.md) for
released integrations and the source build above for this implementation.

## Integrate and verify

Start with the retained guides, using `jacs-compat` wherever an extended CLI
example says `jacs`:

1. [Create and serve an Agent Card](archive/native/jacs/docs/jacsbook/src/guides/a2a-serve.md).
2. [Discover and assess a remote agent](archive/native/jacs/docs/jacsbook/src/guides/a2a-discover.md).
3. [Exchange signed artifacts](archive/native/jacs/docs/jacsbook/src/guides/a2a-exchange.md).
4. Consult the [A2A API reference](archive/native/jacs/docs/jacsbook/src/integrations/a2a.md)
   and [example index](examples/README.md).

Those chapters can contain older version and ES256-default assumptions. Match
the card model, signature representation and algorithm to the peer's supported
profile. A public key supplied with a card does not establish external identity;
apply your configured trust policy and authorization independently. Legacy
`verified` policy establishes same-origin signature/key continuity; `strict`
also checks that a directly signed card uses the explicitly trusted native
root, or validates the scoped binding for an ES256 card. These legacy policies
are separate from the typed v1 verifier.

JACS artifact-envelope key discovery is a separate opt-in native feature. See
[key discovery and verification](docs/key-discovery.md) for DNS/HTTPS lookup,
exact-version fetching and the unchanged caller-pinned A2A 1.0 verification
boundary. Serving a card or JWKS does not automatically enroll a trusted agent.
