# jacs-cli

CLI and MCP server for JACS — cryptographic identity, signing, and verification for AI agents.

```bash
cargo install jacs-cli
```

Or via Homebrew:

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

This installs the `jacs` binary with CLI and MCP server built in.

## Quick start

```bash
export JACS_PRIVATE_KEY_PASSWORD='your-password'

jacs quickstart --name my-agent --domain example.com
jacs document create -f mydata.json
jacs verify signed-document.json
```

## What's new in 0.10.0 — provenance commands

*Why this matters:* shared markdown reviewed by multiple agents and signed images for AI-era provenance now have first-class CLI support — the signature lives inside the artifact, no sidecar JSON required.

### `jacs sign-text` / `jacs verify-text` (inline text signatures)

```bash
# Sign a markdown file — content preserved byte-for-byte, YAML-bodied JACS
# signature block appended at the end.
jacs sign-text README.md

# A second agent counter-signs (multi-signer is unordered)
jacs sign-text README.md  # (run as a different agent)

# Verify per-signer (permissive — missing-sig is exit 2, not an error)
jacs verify-text README.md
# - agent-abc123 (ed25519)   valid
# - agent-def456 (pq2025)    valid

# Strict mode — missing signature exits 1 instead of 2
jacs verify-text --strict README.md
# stderr: "no JACS signature found"

# Override trust store with a directory of <signer_id>.public.pem files
jacs verify-text README.md --key-dir ./trusted-keys/
```

**Exit codes** — permissive verify: `0` valid, `1` invalid signature, `2` missing signature. Strict verify collapses `2` into `1`.

### `jacs sign-image` / `jacs verify-image` / `jacs extract-media-signature`

```bash
# Embed signature in PNG iTXt / JPEG APP11 / WebP XMP
jacs sign-image photo.png --out signed.png

# Refuse to overwrite an existing signature (default is overwrite)
jacs sign-image photo.png --out signed.png --refuse-overwrite

# Verify (permissive)
jacs verify-image signed.png

# Strict verify — missing signature exits 1
jacs verify-image --strict signed.png

# Extract the embedded payload (decoded JSON by default)
jacs extract-media-signature signed.png

# Wire form (base64url)
jacs extract-media-signature signed.png --raw-payload
```

A JACS inline signature proves "agent X signed these canonical bytes at their claimed time." It does not prove first creation or legal ownership.

## MCP server

```bash
jacs mcp
```

The MCP server uses **stdio transport only** — no HTTP endpoints. This is deliberate: the server holds the agent's private key, so it runs as a subprocess of your MCP client. No ports are opened.

Configure in your MCP client (Claude Desktop, Cursor, Claude Code, etc.):

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
- [JACS on crates.io](https://crates.io/crates/jacs)

v0.10.0 | [Apache 2.0 with Common Clause](../LICENSE)
