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

### DID and A2A discovery

```bash
jacs-compat w3c did --origin https://agent.example.com
jacs-compat w3c well-known --origin https://agent.example.com --out ./public
jacs-compat a2a serve --host 127.0.0.1 --port 8080
```

Current source defaults to direct ML-DSA-87 discovery with a `pq2025` root.
Classical roots require explicit `--a2a-algorithm ES256` and an authorized
compatibility key; failures never trigger fallback. The CLI serves legacy
A2A 0.4 discovery, not an A2A messaging endpoint.

The signed origin must match the advertised service. For a non-loopback
listener behind a TLS proxy, supply `--origin https://agent.example.com`.
See the [identity guide](https://github.com/HumanAssisted/JACS/blob/main/docs/identity-standards.md)
for commands, request-proof boundaries and the source/release distinction.

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

Verification uses the caller's explicit public key and algorithm. To sign as
an existing local agent, select its signed config and host password source:

```bash
jacs-compat mcp --profile local-sign --config ./jacs.config.json
```

This grants offline JSON/Agreement operations, not human approval or
administration. File tools require an explicit `JACS_MCP_BASE_DIR` and can keep
plaintext backups. See the [MCP scope and configuration](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacs-mcp/README.md#explicit-local-signing)
for profiles and file policy; the
[native development guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md#password-requirements)
covers headless password setup.

## Links

- [Full Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [CLI Command Reference](https://humanassisted.github.io/JACS/rust/cli.html)
- [MCP Integration](https://humanassisted.github.io/JACS/integrations/mcp.html)
- [JACS on crates.io](https://crates.io/crates/jacs-cli-compat)

Source version 0.15.0 | [Apache-2.0](https://github.com/HumanAssisted/JACS/blob/main/archive/native/LICENSE-APACHE)
