# jacs-cli-compat

CLI and built-in MCP server for JACS: cryptographic identity, signing, and verification for agents and artifacts.

```bash
cargo install jacs-cli-compat --locked
```

This installs `jacs-compat`, the native CLI with its stdio MCP server. For the
portable `jacs` executable, install `jacs-cli` and follow the
[portable CLI guide](https://github.com/HumanAssisted/JACS/blob/main/jacs-cli/README.md).

## Quick start

```bash
export JACS_PRIVATE_KEY_PASSWORD='your-password'

jacs-compat quickstart --name my-agent --domain example.com
jacs-compat document create -f mydata.json --output signed-document.json
jacs-compat verify jacs_data/signed-document.json
```

New agents default to `pq2025` (ML-DSA-87); Ed25519 is an explicit compatibility
choice. Current source exports DID/JWK and signed Agent Cards directly from
the native PQ identity. ES256 ecosystem exports are explicit and require a
native-root-signed compatibility binding. See the
[identity standards guide](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md) for commands,
scopes and peer support. These new standards changes are source work; the
[release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md) describes published 0.15.0.

AP2 mandates and Agreement-v2 credential exports use the explicit ES256
compatibility path and content scopes; they do not imply independent trust or
policy acceptance.

## Provenance commands

### JSON and files

```bash
jacs-compat document create -f mydata.json --output signed-document.json
jacs-compat verify jacs_data/signed-document.json
```

### Markdown and text

```bash
# Append a YAML-bodied JACS signature block at the end of the file.
jacs-compat sign-text README.md

# Another agent can counter-sign the same content.
jacs-compat sign-text README.md

# Permissive verify: 0 valid, 1 invalid, 2 missing signature.
jacs-compat verify-text README.md

# Strict mode treats a missing signature as failure.
jacs-compat verify-text --strict README.md

# Override trust store with <signer_id>.public.pem files.
jacs-compat verify-text README.md --key-dir ./trusted-keys/
```

### Images

```bash
# Embed signature in PNG iTXt, JPEG APP11, or WebP XMP.
jacs-compat sign-image photo.png --out signed.png

# Refuse to overwrite an existing image signature.
jacs-compat sign-image photo.png --out signed.png --refuse-overwrite

jacs-compat verify-image signed.png
jacs-compat verify-image --strict signed.png

# Extract the embedded payload; this does not verify it.
jacs-compat extract-media-signature signed.png
jacs-compat extract-media-signature signed.png --raw-payload
```

JACS proves that an agent signed specific canonical bytes at its claimed time. It does not prove first creation or legal ownership.

### W3C DID interop

```bash
# Export a did:wba identifier while keeping jacsId as the canonical JACS ID.
jacs-compat w3c did --origin https://agent.example.com

# Generate the DID document, agent description, and discovery collection.
jacs-compat w3c did-document --origin https://agent.example.com
jacs-compat w3c agent-description --origin https://agent.example.com
jacs-compat w3c well-known --origin https://agent.example.com --out ./public

# Local demo server for the generated discovery documents.
jacs-compat w3c serve --origin https://agent.example.com --port 8081

# Request-bound DID auth proof demo.
jacs-compat w3c sign-request --method POST --url https://api.example.com/tasks --body '{"ok":true}'
jacs-compat w3c verify-request --method POST --url https://api.example.com/tasks --proof proof.json --did-document did.json --body '{"ok":true}'
```

The W3C view is additive: `jacsId` remains the canonical JACS document identity, and DID documents are generated from the same agent key material.

For an executable end-to-end example that exports discovery artifacts, signs a request-bound DID proof, and verifies both success and failure cases, run the source-matched compatibility binary from the repository root:

```bash
JACS_BIN=/absolute/path/to/source-built/jacs-compat bash archive/native/examples/w3c_did_interop.sh
```

### A2A discovery server

```bash
# Local development: the exact listener origin is signed into the Agent Card.
jacs-compat a2a serve --host 127.0.0.1 --port 8080

# Production: bind behind a TLS reverse proxy and sign its public origin.
jacs-compat a2a serve \
  --host 127.0.0.1 \
  --port 8080 \
  --origin https://agent.example.com

# Explicit classical compatibility for a newly created Ed25519 root.
jacs-compat a2a quickstart --name my-agent --domain example.com \
  --algorithm ed25519 --a2a-algorithm ES256

# Serve an existing identity with its authorized ES256 compatibility key.
jacs-compat a2a serve --a2a-algorithm ES256
```

`--a2a-algorithm` defaults to `ML-DSA-87`, which requires a `pq2025` root.
`--algorithm` on quickstart selects the root algorithm separately; selecting
`ed25519` does not enable compatibility automatically. An existing classical
root requires explicit `--a2a-algorithm ES256` on every serving invocation.
Failures never trigger a fallback. These compatibility CLI commands serve
legacy A2A 0.4 discovery documents, not an A2A messaging endpoint.

The Agent Card's signed `supportedInterfaces[0].url` determines where verifiers
resolve `/.well-known/jwks.json` and, for explicit ES256 compatibility,
`/.well-known/jacs-compat-binding.json`. Without `--origin`, the built-in
plaintext server advertises only an exact loopback `http://HOST:PORT` origin.
Non-loopback listeners fail closed unless an explicit HTTPS origin is supplied;
use that form when TLS terminates at a reverse proxy.

## MCP server

```bash
jacs-compat mcp
```

The MCP server uses stdio transport only. Its default verification-only process
does not load a private key and opens no HTTP port.

Configure in your MCP client:

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs-compat",
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
jacs-compat mcp --profile local-sign --config ./jacs.config.json
```

`JACS_CONFIG` can supply the path instead. This grants only offline local-agent
JSON/Agreement signing, with documents persisted below the config directory.
It is not per-action human approval. File text/image and administrative tools
are not granted by that command. Selecting `JACS_MCP_BASE_DIR` at startup adds
only the five scoped text/image tools, using the same loaded signer; it does
not enable administration. File signing can keep plaintext `.bak` copies; see
the [MCP scope](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/README.md#explicit-local-signing).

For headless/server environments:

```bash
export JACS_CONFIG=/srv/my-project/jacs.config.json
export JACS_PASSWORD_FILE=/run/secrets/jacs-password
export JACS_KEYCHAIN_BACKEND=disabled
jacs-compat mcp --profile local-sign
```

## Links

- [Full Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [CLI Command Reference](https://humanassisted.github.io/JACS/rust/cli.html)
- [MCP Integration](https://humanassisted.github.io/JACS/integrations/mcp.html)
- [JACS on crates.io](https://crates.io/crates/jacs-cli-compat)

Source version 0.15.0 | [Apache-2.0](https://github.com/HumanAssisted/JACS/blob/main/archive/native/LICENSE-APACHE)
