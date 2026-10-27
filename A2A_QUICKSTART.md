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
`jacs::a2a::simple::generate_well_known_documents(&agent, Some("ES256"))`
selects the existing ES256 compatibility path explicitly. See
[DID and post-quantum identity](docs/identity-standards.md) for key formats,
source APIs and trust boundaries.

## Protocol and release scope

The legacy discovery model identifies itself as `0.4.0` and embeds compact JWS
in `signatures[].jws`. The separate
[`a2a::v1` module](archive/native/jacs/src/a2a/v1.rs) supports a bounded A2A 1.0
JSON-RPC card profile. Its `export_agent_card` signs directly with the native
ML-DSA-87 root and emits the standard detached `signatures[].protected` and
`signature` fields. `verify_root_card` validates that signature against an
independently trusted native root and expected identity/version. See the
[library example](docs/identity-standards.md#library-entry-points).

`v1::export_agent_card_es256` is the explicit compatibility alternative.
The [finite report example](archive/native/jacs/examples/a2a_v1_peer.rs) uses
that alternative for its pinned official SDK peer. Its interop evidence covers
ES256, not that peer's ML-DSA support. Neither the typed card API nor the example
implements a general production host. Legacy discovery keeps its original
wire format; a new signing algorithm does not upgrade that format. See the
[checked specification research](docs/research/pq-identity-standards.md).

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
