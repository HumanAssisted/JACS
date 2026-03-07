# MCP Overview

Use MCP when the boundary is model-to-tool inside an application or local workstation. Use [A2A](a2a.md) when the boundary is agent-to-agent across organizations or services.

## Choose The MCP Path

There are three supported ways to use JACS with MCP today:

1. **Run `jacs mcp`** when you want a ready-made MCP server with the broadest tool surface.
2. **Wrap an existing MCP transport** when you already have an MCP server or client and want signed JSON-RPC.
3. **Register JACS as MCP tools** when you want the model to call signing, verification, agreement, A2A, or trust operations directly.

## Best Fit By Runtime

| Runtime | Best starting point | What it gives you |
|---|---|---|
| Rust | `jacs-mcp` | Full MCP server with document, agreement, trust, A2A, and audit tools |
| Python | `jacs.mcp` or `jacs.adapters.mcp` | Local SSE transport security or FastMCP tool registration |
| Node.js | `@hai.ai/jacs/mcp` | Transport proxy or MCP tool registration for existing SDK-based servers |

## Important Constraints

- **Python MCP wrappers are local-only.** `JACSMCPClient`, `JACSMCPServer`, and `jacs_call()` enforce loopback URLs.
- **Unsigned fallback is off by default.** Both Python and Node fail closed unless you explicitly allow unsigned fallback.
- **Node has two factories.** `createJACSTransportProxy()` takes a loaded `JacsClient` or `JacsAgent`; `createJACSTransportProxyAsync()` is the config-path variant.

## 1. Ready-Made Server: `jacs mcp`

Install the unified binary and start the MCP server:

```bash
cargo install jacs-cli
jacs mcp
```

The MCP server is built into the `jacs` binary (stdio transport only, no HTTP). It includes document signing, agreements, trust store operations, A2A tools, and security audit tools. See `jacs-mcp/README.md` in the repo for the full tool list and client configuration examples.

## 2. Transport Security Around Your Existing MCP Code

### Python

Use `jacs.mcp` when you already have a FastMCP server or client and want transparent signing around the SSE transport:

```python
from fastmcp import FastMCP
from jacs.mcp import JACSMCPServer

mcp = JACSMCPServer(FastMCP("Secure Server"), "./jacs.config.json")
```

For clients:

```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient("http://localhost:8000/sse", "./jacs.config.json")
```

Helpful utilities in the same module:

- `create_jacs_mcp_server()` for a one-line FastMCP server
- `jacs_middleware()` for explicit Starlette middleware wiring
- `jacs_call()` for one-off authenticated local calls

See [Python MCP Integration](../python/mcp.md) for the detailed patterns.

### Node.js

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

The Node tool set is intentionally smaller than the Rust MCP server. Use `jacs mcp` when you need the largest supported MCP surface.

## Example Paths In This Repo

- `jacs-mcp/README.md`
- `jacspy/examples/mcp/server.py`
- `jacspy/examples/mcp/client.py`
- `jacsnpm/examples/mcp.stdio.server.js`
- `jacsnpm/examples/mcp.stdio.client.js`

## Related Guides

- [Python MCP Integration](../python/mcp.md)
- [Node.js MCP Integration](../nodejs/mcp.md)
- [A2A Interoperability](a2a.md)
- [Python Framework Adapters](../python/adapters.md)
