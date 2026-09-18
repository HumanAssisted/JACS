# Quick Start Guide

Get a persistent agent identity, sign data, and verify it.

## Let your agent sign documents with MCP

The unified `jacs` binary includes a stdio-only MCP server. After installing
it and creating an identity with the [CLI setup](#cli), or selecting an
existing signed config, explicitly enable local signing:

```bash
jacs mcp --profile local-sign --config /absolute/path/to/jacs.config.json
```

Configure your MCP client with the same arguments:

```json
{
  "mcpServers": {
    "jacs": {
      "command": "jacs",
      "args": ["mcp", "--profile", "local-sign", "--config", "/absolute/path/to/jacs.config.json"]
    }
  }
}
```

Local signing uses the selected config's persistent encrypted keys and its
[keychain or password source](#password-bootstrap). It grants agent signing
authority; a signature does not establish a person's approval of the content.
Key and trust administration are not enabled by this profile.

To verify documents without creating an identity or unlocking private keys,
use the default verification-only configuration instead:

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

The default `verify-only` profile stays verification-only when a config or
password is available; selecting `local-sign` is explicit. Set
`JACS_MCP_BASE_DIR` only when you intend to add scoped text/image
file tools to `local-sign`; no content directory is granted implicitly. See the
[canonical MCP guide](../integrations/mcp.md#1-ready-made-server-jacs-mcp) for
file scope, overwrite behavior and the actual tool inventory.

## CLI

Install the unified CLI/MCP binary:

```bash
cargo install jacs-cli
```

Create or load an agent, then sign and verify a JSON file:

```bash
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'

jacs quickstart --name my-agent --domain my-agent.example.com
jacs document create -f mydata.json --output signed-document.json
jacs verify jacs_data/signed-document.json
```

Homebrew is also supported:

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

## Python

```bash
pip install jacs
```

```python
import jacs.simple as jacs

info = jacs.quickstart(name="my-agent", domain="my-agent.example.com")
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

## Node.js

{{#include ../_snippets/node-registry-status.md}}

```bash
npm install @hai.ai/jacs
```

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});

const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

## Sign Markdown or text

```bash
jacs sign-text README.md
jacs verify-text README.md
jacs verify-text --strict README.md
```

`sign-text` appends a `-----BEGIN JACS SIGNATURE-----` block at the end of the file. The original content remains readable and can be counter-signed by another agent.

See [Inline Text Signatures](../guides/inline-text-signing.md) for multi-signer flows, strict mode, and `--key-dir`.

## Sign images

```bash
jacs sign-image photo.png --out signed.png
jacs verify-image signed.png
jacs extract-media-signature signed.png
```

JACS embeds the signature in PNG, JPEG, or WebP metadata. See [Image and Media Signatures](../guides/media-signing.md) for overwrite policy, robust mode, and verification details.

## Password bootstrap

The Rust CLI needs a password source before it can sign:

```bash
# CI/server
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'

# Developer workstation
jacs keychain set --agent-id <YOUR_AGENT_UUID>

# File-based secret
export JACS_PASSWORD_FILE=/secure/path/jacs-password.txt
```

If both `JACS_PRIVATE_KEY_PASSWORD` and `JACS_PASSWORD_FILE` are set, the CLI fails fast to avoid ambiguity. The OS keychain is only consulted when neither environment source is set.

Python and Node quickstart can auto-generate a secure password if `JACS_PRIVATE_KEY_PASSWORD` is unset. In production, set `JACS_PRIVATE_KEY_PASSWORD` explicitly.

## Algorithm

The default signing algorithm is `pq2025` (ML-DSA-87 / FIPS-204). Use the
user-facing `ed25519` choice if you need a smaller classical signature. JACS
stores and emits the canonical Ed25519 wire label as `ring-Ed25519`:

```bash
jacs quickstart --name my-agent --domain my-agent.example.com --algorithm ed25519
```

## Next steps

- [Which Integration?](decision-tree.md)
- [Verifying Signed Documents](verification.md)
- [MCP Overview](../integrations/mcp.md)
