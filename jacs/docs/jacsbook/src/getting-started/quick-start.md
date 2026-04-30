# Quick Start Guide

Get a persistent agent identity, sign data, and verify it.

## CLI

Install the unified CLI/MCP binary:

```bash
cargo install jacs-cli
```

Create or load an agent, then sign and verify a JSON file:

```bash
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'

jacs quickstart --name my-agent --domain my-agent.example.com
jacs document create -f mydata.json
jacs verify signed-document.json
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

## Start the MCP server

The MCP server is built into the `jacs` binary. It uses stdio transport only.

```bash
jacs mcp
```

Example MCP client config:

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

The default signing algorithm is `pq2025` (ML-DSA-87 / FIPS-204). Use `ring-Ed25519` if you need a smaller classical signature:

```bash
jacs quickstart --name my-agent --domain my-agent.example.com --algorithm ring-Ed25519
```

## Next steps

- [Which Integration?](decision-tree.md)
- [Verifying Signed Documents](verification.md)
- [MCP Overview](../integrations/mcp.md)
