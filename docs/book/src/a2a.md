# Use JACS with A2A

Use native JACS to publish signed Agent Cards and sign artifacts. Discovery
export does not implement a messaging endpoint: your application must serve the
skills and URL it advertises. The portable MCP server has no A2A transport.

## Build this checkout

The binding build uses Python 3.11+, Rust 1.97 through rustup, a C compiler/linker, Make and Perl. On Linux, the default keychain build also needs `pkg-config` and D-Bus development headers (`libdbus-1-dev` on Debian/Ubuntu). The official JavaScript SDK smoke requires Node.js 24.7+ and npm.

These instructions use current source, including direct ML-DSA-87 card signing.
The published 0.15.0 inventory does not establish availability of these changes.
From the repository root, with Rust 1.97+ and [native build prerequisites](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md):

```sh
cargo install --locked --path archive/native/jacs-cli
```

Provide the native key password through your host secret source or configured
keychain; keep it out of command arguments and committed files. Use a private
working directory for persistent keys and `jacs.config.json`.

## Serve local discovery

The default direct-PQ walkthrough requires an ML-DSA-87 root. Loading an older Ed25519 identity does not migrate it; explicitly upgrade it before using this profile.

```sh
jacs-compat a2a quickstart --name example-agent --domain agent.example.com
```

This creates a persistent PQ identity, or loads the existing identity as-is and serves discovery on
`http://127.0.0.1:8080`. In another terminal:

```sh
curl --fail http://127.0.0.1:8080/.well-known/agent-card.json
curl --fail http://127.0.0.1:8080/.well-known/jwks.json
```

The CLI uses the legacy `0.4.0` card model with compact `signatures[].jws`.
Default source discovery publishes five documents and signs with the persisted
PQ root; its JWK has `kty: "AKP"` and `alg: "ML-DSA-87"`. Fetching these documents
only checks that the server responds—it does not verify a trusted identity.

For an existing config, restart with `jacs-compat a2a serve`. Behind a TLS
reverse proxy, pass `--origin https://agent.example.com`; the signed public
origin must match the service clients use. A classical peer requires explicit
`--a2a-algorithm ES256` and the scoped compatibility binding (a sixth document).
Selecting an Ed25519 root alone does not enable ES256 card signing.

## Export an A2A 1.0 card

The public Node/Python APIs accept an explicit `protocolVersion: "1.0"`, actual
messaging URL, nonempty skills and content modes. Omitting these options keeps
legacy discovery. Build the Node binding with `make build-jacsnpm`, then install
its source package in your consuming project:

```sh
npm install /absolute/path/to/JACS/archive/native/jacsnpm
```

Save this as `discovery.cjs` and run `node discovery.cjs`:

```javascript
const { JacsClient } = require('@hai.ai/jacs/client');
const { buildWellKnownDocuments } = require('@hai.ai/jacs/a2a-server');

async function main() {
  const client = await JacsClient.quickstart({
    name: 'report-agent', domain: 'agent.example.com',
  });
  const documents = buildWellKnownDocuments(client, {
    protocolVersion: '1.0',
    messagingUrl: 'https://agent.example.com/a2a',
    skills: [{ id: 'report', name: 'Report', description: 'Return a report', tags: ['report'] }],
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['application/json'],
  });
  console.log(JSON.stringify(documents['/.well-known/agent-card.json'], null, 2));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
```

The resulting card uses `supportedInterfaces` with protocol version `1.0` and
detached `signatures[].protected` / `signature` fields. This example exports a
card; it does not start the advertised `/a2a` handler. Preserve the encrypted
identity and its host-managed password between runs.

Python exposes the same option names through
`client.get_a2a().generate_well_known_documents(discovery_options=options)`;
see the [binding examples](https://github.com/HumanAssisted/JACS/blob/main/A2A_QUICKSTART.md#a2a-10-from-nodejs-or-python).

## Verify and exchange a message

Before choosing a transport, verify the card with an independently trusted key,
expected identity/version and algorithm. For direct PQ v1 cards, native Rust
provides `jacs::a2a::v1::verify_root_card`; official SDK verification also needs
trusted key selection. Legacy `verified`/`strict` policy helpers are not v1 parsers.

The [official SDK examples](https://github.com/HumanAssisted/JACS/blob/main/archive/native/examples/a2a_v1_sdk/README.md)
start real SDK servers/clients, verify cards and exchange one signed report.
For the JavaScript example, use Node 24.7+ with ML-DSA WebCrypto, then run from
the repository root after building the binding:

```sh
npm ci --ignore-scripts --prefix archive/native/examples/a2a_v1_sdk
npm test --prefix archive/native/examples/a2a_v1_sdk
```

The pinned JavaScript SDK 1.3.0 supports direct ML-DSA-87 through `jose` 6.2.3.
The Python SDK 1.3.0 example uses explicit ES256 because its PyJWT backend lacks
ML-DSA verification; the native root remains PQ. The tests include modified
cards/signatures and untrusted-root rejection, not every A2A capability.

Next: [signed artifacts](native/guides/a2a-exchange.html),
[discovery trust policy](native/guides/a2a-discover.html) and
[W3C DID export](w3c-did.md). Apply application authorization after verification;
card discovery, cached freshness and signature validity do not grant it.
