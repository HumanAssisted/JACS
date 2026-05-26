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
jacs document create -f mydata.json
jacs verify signed-document.json
```

## Provenance commands

### JSON and files

```bash
jacs document create -f mydata.json
jacs verify signed-document.json
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

## MCP server

```bash
jacs mcp
```

The MCP server uses stdio transport only. It runs as a subprocess of your MCP client, holds the private key locally, and opens no HTTP port.

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

For headless/server environments:

```bash
export JACS_CONFIG=/srv/my-project/jacs.config.json
export JACS_PASSWORD_FILE=/run/secrets/jacs-password
export JACS_KEYCHAIN_BACKEND=disabled
jacs mcp
```

## Links

- [Full Documentation](https://humanassisted.github.io/JACS/)
- [Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [CLI Command Reference](https://humanassisted.github.io/JACS/rust/cli.html)
- [MCP Integration](https://humanassisted.github.io/JACS/integrations/mcp.html)
- [JACS on crates.io](https://crates.io/crates/jacs-cli)

v0.11.1 | [Apache-2.0](../LICENSE-APACHE)
