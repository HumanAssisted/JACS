# jacs-cli

CLI and built-in MCP server for JACS: cryptographic identity, signing, and verification for agents and artifacts.

```bash
cargo install jacs-cli
```

Or via Homebrew:

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

This installs the `jacs` binary with the CLI and stdio MCP server built in.

## Quick start

```bash
export JACS_PRIVATE_KEY_PASSWORD='your-password'

jacs quickstart --name my-agent --domain example.com
jacs document create -f mydata.json --output signed-document.json
jacs verify jacs_data/signed-document.json
```

New agents default to post-quantum `pq2025` (ML-DSA-87); pass
`--algorithm ed25519` when explicitly required. Persistent agents also get
an ES256 ecosystem compatibility key (role `ecosystem_signing`) for
W3C/JWKS/A2A interop — skip it with `--no-compat-key` on `init` or
`agent create`, and add it to a pre-existing agent with
`jacs agent add-compat-key`.

Ecosystem exports are gated by a native-root-signed binding:
`jacs agent issue-compat-binding --scopes ...` grants scopes (content
scopes like `ap2-mandate` and `agreement-vc` are never auto-issued).
`jacs ap2 export-mandate --input <JSON, path, or - for stdin>` emits an
AP2 merchant-authorization mandate as a detached ES256 JWS, and
`jacs agreement-v2 export-vc --agreement <...>` emits an Agreement-v2
document as a W3C Verifiable Credential with an `ecdsa-jcs-2019` Data
Integrity proof. Both verify with stock tooling classically; native-root
trust additionally requires the binding
(`jacs agent export-compat-binding`).

## Provenance commands

### JSON and files

```bash
jacs document create -f mydata.json --output signed-document.json
jacs verify jacs_data/signed-document.json
```

### Markdown and text

```bash
# Append a YAML-bodied JACS signature block at the end of the file.
jacs sign-text README.md

# Another agent can counter-sign the same content.
jacs sign-text README.md

# Permissive verify: 0 valid, 1 invalid, 2 missing signature.
jacs verify-text README.md

# Strict mode treats a missing signature as failure.
jacs verify-text --strict README.md

# Override trust store with <signer_id>.public.pem files.
jacs verify-text README.md --key-dir ./trusted-keys/
```

### Images

```bash
# Embed signature in PNG iTXt, JPEG APP11, or WebP XMP.
jacs sign-image photo.png --out signed.png

# Refuse to overwrite an existing image signature.
jacs sign-image photo.png --out signed.png --refuse-overwrite

jacs verify-image signed.png
jacs verify-image --strict signed.png

# Extract the embedded payload; this does not verify it.
jacs extract-media-signature signed.png
jacs extract-media-signature signed.png --raw-payload
```

JACS proves that an agent signed specific canonical bytes at its claimed time. It does not prove first creation or legal ownership.

### W3C DID interop

```bash
# Export a did:wba identifier while keeping jacsId as the canonical JACS ID.
jacs w3c did --origin https://agent.example.com

# Generate the DID document, agent description, and discovery collection.
jacs w3c did-document --origin https://agent.example.com
jacs w3c agent-description --origin https://agent.example.com
jacs w3c well-known --origin https://agent.example.com --out ./public

# Local demo server for the generated discovery documents.
jacs w3c serve --origin https://agent.example.com --port 8081

# Request-bound DID auth proof demo.
jacs w3c sign-request --method POST --url https://api.example.com/tasks --body '{"ok":true}'
jacs w3c verify-request --method POST --url https://api.example.com/tasks --proof proof.json --did-document did.json --body '{"ok":true}'
```

The W3C view is additive: `jacsId` remains the canonical JACS document identity, and DID documents are generated from the same agent key material.

For an executable end-to-end example that exports discovery artifacts, signs a request-bound DID proof, and verifies both success and failure cases, run `examples/w3c_did_interop.sh` from the repository root.

### A2A discovery server

```bash
# Local development: the exact listener origin is signed into the Agent Card.
jacs a2a serve --host 127.0.0.1 --port 8080

# Production: bind behind a TLS reverse proxy and sign its public origin.
jacs a2a serve \
  --host 127.0.0.1 \
  --port 8080 \
  --origin https://agent.example.com
```

The Agent Card's signed `supportedInterfaces[0].url` determines where verifiers
resolve `/.well-known/jwks.json` and
`/.well-known/jacs-compat-binding.json`. Without `--origin`, the built-in
plaintext server advertises only an exact loopback `http://HOST:PORT` origin.
Non-loopback listeners fail closed unless an explicit HTTPS origin is supplied;
use that form when TLS terminates at a reverse proxy.

## MCP server

```bash
jacs mcp
```

The MCP server uses stdio transport only. Its default verification-only process
does not load a private key and opens no HTTP port.

Configure in your MCP client:

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp"]
    }
  }
}
```

The default `verify-only` profile exposes only exact-byte document integrity
verification with a caller-supplied public key and algorithm. An explicitly
supplied config is public-only and never loads/decrypts a signing key. The closed profile names are `verify-only`,
`local-sign`, `trust-admin`, and compatibility-only `legacy-core`. When
`--profile` is absent, `JACS_MCP_PROFILE` is consulted before falling back to
`verify-only`; explicit CLI selection wins, and unknown values fail startup.
A profile name alone does not load a signer. Use the existing signed config
and normal keychain/password source explicitly:

```bash
jacs mcp --profile local-sign --config ./jacs.config.json
```

`JACS_CONFIG` can supply the path instead. This grants only offline local-agent
JSON/Agreement signing, with documents persisted below the config directory.
It is not per-action human approval. File text/image and administrative tools
are not granted by that command. Selecting `JACS_MCP_BASE_DIR` at startup adds
only the five scoped text/image tools, using the same loaded signer; it does
not enable administration. File signing can keep plaintext `.bak` copies; see
the [MCP scope](../jacs-mcp/README.md#explicit-local-signing).

For headless/server environments:

```bash
export JACS_CONFIG=/srv/my-project/jacs.config.json
export JACS_PASSWORD_FILE=/run/secrets/jacs-password
export JACS_KEYCHAIN_BACKEND=disabled
jacs mcp --profile local-sign
```

## Links

- [Full Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [CLI Command Reference](https://humanassisted.github.io/JACS/rust/cli.html)
- [MCP Integration](https://humanassisted.github.io/JACS/integrations/mcp.html)
- [JACS on crates.io](https://crates.io/crates/jacs-cli)

v0.11.4 | [Apache-2.0](../LICENSE-APACHE)
