# Use JACS with W3C DIDs

JACS exports a DID Core document for its implemented `did:wba` method, using the
persistent native signing key. It does not provide a general DID resolver or
`did:web`/`did:key` exports. The commands below describe current source; published
0.15.0 packages are a separate release baseline.

## Build and create an identity

Use a C compiler/linker and Rust 1.97. On Linux the default keychain build also requires `pkg-config` and D-Bus development headers (`libdbus-1-dev` on Debian/Ubuntu).

From the repository root, with Rust 1.97+ and [native build prerequisites](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md):

```sh
cargo install --locked --path archive/native/jacs-cli
```

In a private working directory, supply `JACS_PRIVATE_KEY_PASSWORD` through your
host secret mechanism or use the configured native keychain, then run:

```sh
jacs-compat quickstart --name example-agent --domain agent.example.com
jacs-compat w3c did --origin https://agent.example.com
jacs-compat w3c did-document --origin https://agent.example.com > did.json
jacs-compat w3c well-known --origin https://agent.example.com --out discovery
```

The identifier has the form `did:wba:agent.example.com:agent:<jacsId>`.
The DID document uses DID v1 / Controlled Identifiers v1 contexts and a
`JsonWebKey` verification method. For a `pq2025` root, its public JWK uses
`kty: "AKP"`, `alg: "ML-DSA-87"` and base64url public-key bytes in `pub`.
Repeated exports retain that root key and its thumbprint-derived JWK `kid`.

`well-known` writes three public documents and prints their paths:

- `/.well-known/agent-descriptions`
- `/agent/<jacsId>/description.json`
- `/agent/<jacsId>/did.json`

Publish them at those paths under the controlling HTTPS origin. Exporting files
does not deploy them or prove domain control. For a local inspection server,
use `jacs-compat w3c serve --origin https://agent.example.com --host 127.0.0.1 --port 8081`;
this is a plaintext demo listener, not deployment of the claimed HTTPS origin.

## Test a request-bound proof

JACS has a request-proof JSON format, `JacsW3cRequestProof` with scheme `DIDWba`.
It is **not** ANP HTTP Message Signatures. For a local round trip, sign the
actual method, target URL and body, then verify the same values:

```sh
printf '%s' '{"task":"review"}' > request.json
jacs-compat w3c sign-request --origin https://agent.example.com \
  --method POST --url 'https://api.example.com/tasks?priority=high' \
  --body-file request.json > proof.json
jacs-compat w3c verify-request --proof proof.json --did-document did.json \
  --method POST --url 'https://api.example.com/tasks?priority=high' \
  --body-file request.json
```

Success prints JSON with `valid: true` and `expectedRequestChecked: true`.
A substituted body or URL fails verification. The default maximum proof age is
300 seconds. In this local test, `did.json` is your own exported document; a
receiver must obtain the DID document under an independently trusted policy,
check its verification relationship and enforce current authorization/revocation.

Production hosts must also enforce replay protection across their deployment.
A fresh CLI process does not retain previous processes' nonce history. See
[replay-store deployment](native/advanced/security.html#replay-store-deployment)
and the [request-proof reference](native/integrations/did.html#jacs-specific-request-proofs).

## Compatibility and limits

Explicit ES256 compatibility uses a persisted key and a scoped binding signed
by the native root. A peer without ML-DSA support needs that deliberate
integration; an error never triggers a downgrade. Current VC/Data Integrity
exports retain the ES256 path. An AKP JWK is not a claim of a finalized
ML-DSA-87 Data Integrity cryptosuite.

Next: [A2A discovery](a2a.md), [native DID reference](native/integrations/did.html)
and [standards evidence](https://github.com/HumanAssisted/JACS/blob/main/docs/research/pq-identity-standards.md).
DID document structure, method interoperability and real-world identity trust
are separate checks.
