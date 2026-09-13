# MCP Overview

Use MCP when the boundary is model-to-tool inside an application or local workstation. Use [A2A](a2a.md) when the boundary is agent-to-agent across organizations or services.

## Choose The MCP Path

JACS offers three MCP integration surfaces:

1. **Run `jacs mcp`** for local document verification without signing keys.
   Select `--profile local-sign` with an existing signed config to let the
   local client sign as that agent.
2. **Wrap an existing MCP transport** when you already have an MCP server or client and want signed JSON-RPC.
3. **Register JACS as MCP tools** when you want the model to call signing, verification, agreement, A2A, or trust operations directly.

## Best Fit By Runtime

| Runtime | Best starting point | What it gives you |
|---|---|---|
| Rust CLI | `jacs mcp` | Verification by default; explicit local signing of documents and Agreement-v2 artifacts, with optional scoped text/image tools |
| Python | `jacs.mcp` or `jacs.adapters.mcp` | Local SSE transport security or FastMCP tool registration |
| Node.js | `@hai.ai/jacs/mcp` | Transport proxy or MCP tool registration for existing SDK-based servers |

## Important Constraints

- **Python MCP wrappers are local-only.** `JACSMCPClient`, `JACSMCPServer`, and `jacs_call()` enforce loopback URLs.
- **Unsigned fallback is off by default.** Both Python and Node fail closed unless you explicitly allow unsigned fallback.
- **Node has two factories.** `createJACSTransportProxy()` takes a loaded `JacsClient` or `JacsAgent`; `createJACSTransportProxyAsync()` is the config-path variant.
- **The native server's profiles do not configure the Python or Node adapters.**
  Those integrations have their own transport, key-loading and authorization
  requirements; the examples below do not inherit the native server's closed
  local-sign inventory.
- **Signatures are provenance, not human approval.** Supplied-key verification
  checks integrity; it does not establish truth, identity, authorization,
  publication permission or Agreement policy acceptance.

## 1. Ready-Made Server: `jacs mcp`

Install the unified binary and start a verification-only server. No identity
creation or private-key password is required:

```bash
cargo install jacs-cli
jacs mcp
```

Configure a compatible MCP client with:

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

The default `verify-only` profile exposes only `jacs_verify_document`; callers
supply the public key and algorithm. An explicitly supplied `--config` or
`JACS_CONFIG` loads public-only configuration without unlocking private keys.

To sign, reuse an existing signed config, or run `jacs init` once in the
directory where you want to keep the agent identity. Keep using its normal
keychain/password source and select it explicitly:

```bash
jacs mcp --profile local-sign --config /absolute/path/to/jacs.config.json
```

Use those same arguments in the MCP client:

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

`JACS_CONFIG` can supply the config path instead. Local signing requires a
valid signed config and persistent encrypted keys in filesystem storage; it
does not discover config implicitly or create a replacement identity. Never
send a password as a tool argument or embed it in client JSON. Prefer an
owner-readable `JACS_PASSWORD_FILE` or the configured OS keychain.

This profile exposes nine JSON/Agreement-v2 tools when Agreement tools are
compiled. To add exactly five text/image tools, grant an existing content
directory explicitly at process startup:

```bash
JACS_MCP_BASE_DIR=/absolute/path/to/content jacs mcp --profile local-sign --config /absolute/path/to/jacs.config.json
```

There is no implicit working-directory grant. File tools reject traversal and
symlinks and stay beneath the selected directory. Replacing a distinct existing
output requires `JACS_MCP_OVERWRITE_OK=1`; explicit in-place signing remains
available. Normal backups contain the original plaintext file, so protect them
alongside the content. A content root never expands `verify-only`.
Signing persists ordinary JACS documents under the config directory's
`documents/` directory and grants agent signing authority, not human approval.

An explicit `--profile` overrides `JACS_MCP_PROFILE`; unknown values fail
startup. Historical `core`/`full` recipes are obsolete; `trust-admin` and
compatibility-only `legacy-core` remain unavailable. Key administration,
trust management, A2A and attestation tools are not enabled by `local-sign`.
The compiled 42-tool contract is not a runtime grant: use `tools/list` to see
the process's actual authorized inventory.

The native server uses stdio only: stdout carries MCP JSON-RPC and diagnostics
go to stderr. It uses RMCP 3.3.0, supporting date-versioned MCP `2026-07-28`
and legacy `2025-11-25` initialization; these are distinct from SDK major
versions such as the TypeScript SDK v2. See the
[crate MCP README](https://github.com/HumanAssisted/JACS/blob/main/jacs-mcp/README.md)
for the complete local-signing and response-error contract.

## 2. Transport Security Around Your Existing MCP Code

### Python

Use `jacs.mcp` when you already have a FastMCP server or client and want transparent signing around the SSE transport:

```python
from fastmcp import FastMCP
from jacs.mcp import JACSMCPServer

mcp = JACSMCPServer(
    FastMCP("Secure Server"),
    "./jacs.config.json",
    allowed_peer_agent_ids=["CLIENT_AGENT_ID"],
)
```

For clients:

```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient(
    "http://localhost:8000/sse",
    "./jacs.config.json",
    expected_peer_agent_id="SERVER_AGENT_ID",
)
```

Helpful utilities in the same module:

- `create_jacs_mcp_server()` for a one-line FastMCP server
- `jacs_middleware()` for explicit Starlette middleware wiring
- `jacs_call()` for one-off authenticated local calls

See [Python MCP Integration](../python/mcp.md) for the detailed patterns.

### Node.js

{{#include ../_snippets/node-registry-status.md}}

Use the transport proxy when you already have an MCP transport:

```typescript
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { JacsClient } from '@hai.ai/jacs/client';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const client = await JacsClient.quickstart({
  name: 'mcp-agent',
  domain: 'mcp.local',
});

const transport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(transport, client, 'server');
```

If you only have a config path:

```typescript
import { createJACSTransportProxyAsync } from '@hai.ai/jacs/mcp';

const secureTransport = await createJACSTransportProxyAsync(
  transport,
  './jacs.config.json',
  'server',
);
```

See [Node.js MCP Integration](../nodejs/mcp.md) for examples and tool registration.

## 3. Register JACS Operations As MCP Tools

This is different from transport security. Here the model gets explicit MCP tools such as `jacs_sign_document`, `jacs_verify_document`, agreement helpers, and trust helpers.

### Python

```python
from fastmcp import FastMCP
from jacs.client import JacsClient
from jacs.adapters.mcp import (
    register_jacs_tools,
    register_a2a_tools,
    register_trust_tools,
)

client = JacsClient.quickstart(name="mcp-agent", domain="mcp.local")
mcp = FastMCP("JACS Tools")
register_jacs_tools(mcp, client=client)
register_a2a_tools(mcp, client=client)
register_trust_tools(mcp, client=client)
```

### Node.js

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { JacsClient } from '@hai.ai/jacs/client';
import { registerJacsTools } from '@hai.ai/jacs/mcp';

const server = new Server(
  { name: 'jacs-tools', version: '1.0.0' },
  { capabilities: { tools: {} } },
);

const client = await JacsClient.quickstart({
  name: 'mcp-agent',
  domain: 'mcp.local',
});

registerJacsTools(server, client);
```

Choose the native `jacs mcp` server for its explicit local-signing boundary.
Tool registration in an existing Node or Python server is a separate
integration; review that server's exposed operations and authorization.

### Provenance MCP tools

With `local-sign` and an explicit `JACS_MCP_BASE_DIR`, the native server adds
the following tools for inline text and image provenance. They cover the
same surface as the [`sign-text`](../guides/inline-text-signing.md) and
[`sign-image`](../guides/media-signing.md) CLI verbs:

- `jacs_sign_text` — append a YAML-bodied signature block to a markdown / text file.
- `jacs_verify_text` — verify all signature blocks in a file (permissive default; `strict` opt-in).
- `jacs_sign_image` — embed a signature in PNG iTXt / JPEG APP11 / WebP XMP.
- `jacs_verify_image` — verify the embedded image signature (permissive default; `strict` opt-in).
- `jacs_extract_media_signature` — read out the embedded signature payload (decoded JSON by default; `raw_payload` opt-in for the base64url wire form).

## Example Paths In This Repo

- `jacspy/examples/mcp/server.py`
- `jacspy/examples/mcp/client.py`
- `jacsnpm/examples/mcp.stdio.server.js`
- `jacsnpm/examples/mcp.stdio.client.js`

## Related Guides

- [Python MCP Integration](../python/mcp.md)
- [Node.js MCP Integration](../nodejs/mcp.md)
- [A2A Interoperability](a2a.md)
- [Python Framework Adapters](../python/adapters.md)
