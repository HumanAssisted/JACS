# Quick Start Guide

Get a persistent agent identity, sign data, and verify it.

## Start with MCP

Install the portable CLI and start its default verification-only MCP server:

```bash
cargo install jacs-cli --locked
jacs mcp
```

```json
{
  "mcpServers": {
    "jacs": { "command": "jacs", "args": ["mcp"] }
  }
}
```

Verification requires independently trusted public evidence. A valid signature
proves integrity under that key; your application decides identity and authority.

## Portable CLI

Create an encrypted identity, sign JSON and verify with the exported public identity:

```bash
mkdir -m 700 .jacs
jacs create --output .jacs/agent.json > public-identity.json
printf '%s' '{"message":"hello"}' | jacs sign --agent .jacs/agent.json --input - > signed.json
jacs verify --public-identity public-identity.json --input signed.json
```

The terminal prompts for the password. For an MCP client that can provide the
host's configured secret source, explicitly enable signing with
`jacs mcp --profile local-sign --agent /absolute/path/to/.jacs/agent.json`.
Use the same arguments in its `mcpServers` configuration. See the
[current MCP guide](https://humanassisted.github.io/JACS/mcp-quickstart.html)
for secret handling and the available tools.

The remaining native examples use a separate installation:

```bash
cargo install jacs-cli-compat --locked
jacs-compat quickstart --name my-agent --domain my-agent.example.com
```

This creates `jacs.config.json` and persistent native keys for direct libraries
and extended text/image commands. The native MCP profiles use `jacs-compat mcp`;
see [extended profiles](https://humanassisted.github.io/JACS/native-mcp.html).

## Python

```bash
python -m pip install jacs==0.15.0
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
npm install --save-exact @hai.ai/jacs@0.15.0
```

```javascript
import * as jacs from '@hai.ai/jacs/simple';

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
jacs-compat sign-text README.md
jacs-compat verify-text README.md
jacs-compat verify-text --strict README.md
```

`sign-text` appends a `-----BEGIN JACS SIGNATURE-----` block at the end of the file. The original content remains readable and can be counter-signed by another agent.

See [Inline Text Signatures](../guides/inline-text-signing.md) for multi-signer flows, strict mode, and `--key-dir`.

## Sign images

```bash
jacs-compat sign-image photo.png --out signed.png
jacs-compat verify-image signed.png
jacs-compat extract-media-signature signed.png
```

JACS embeds the signature in PNG, JPEG, or WebP metadata. See [Image and Media Signatures](../guides/media-signing.md) for overwrite policy, robust mode, and verification details.

## Native password bootstrap

The compatibility CLI needs a password source before it can sign:

```bash
# CI/server
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'

# Developer workstation
jacs-compat keychain set --agent-id <YOUR_AGENT_UUID>

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
jacs-compat quickstart --name my-agent --domain my-agent.example.com --algorithm ed25519
```

## Next steps

- [Which Integration?](decision-tree.md)
- [Verifying Signed Documents](verification.md)
- [MCP Overview](../integrations/mcp.md)
