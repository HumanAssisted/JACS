# MCP Integration (Node.js)

Node has two MCP stories:

1. **Wrap an MCP transport** with signing and verification
2. **Register JACS operations as MCP tools** on an existing server

If you want a full out-of-the-box server instead, prefer the Rust `jacs-mcp` binary.

## Install

```bash
npm install @hai.ai/jacs @modelcontextprotocol/sdk
```

## 1. Wrap A Transport

Use this when you already have an MCP server or client and want signed JSON-RPC messages.

### With a loaded client

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

### With only a config path

```typescript
import { createJACSTransportProxyAsync } from '@hai.ai/jacs/mcp';

const secureTransport = await createJACSTransportProxyAsync(
  transport,
  './jacs.config.json',
  'server',
);
```

`createJACSTransportProxy()` does **not** take a config path. Use the async factory when the agent is not already loaded.

## 2. Register JACS Tools On Your MCP Server

Use this when the model should explicitly call JACS operations such as signing, verification, agreement creation, or trust-store inspection.

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

The registered tool set includes:

- document signing and verification
- agreement helpers
- audit and agent-info helpers
- trust-store helpers
- setup and registry helper stubs

For lower-level integration, use `getJacsMcpToolDefinitions()` plus `handleJacsMcpToolCall()`.

## Failure Behavior

The transport proxy is not permissive by default.

- Signing or verification failures fail closed unless you explicitly pass `allowUnsignedFallback: true`
- `createJACSTransportProxy()` expects a real `JacsClient` or `JacsAgent`, not an unloaded shell

## Common Pattern

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { JacsClient } from '@hai.ai/jacs/client';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});

const server = new McpServer({ name: 'my-server', version: '1.0.0' });
const transport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(transport, client, 'server');

await server.connect(secureTransport);
```

For stdio servers, keep logs on `stderr`, not `stdout`.

## Example Paths In This Repo

- `jacsnpm/examples/mcp.stdio.server.js`
- `jacsnpm/examples/mcp.stdio.client.js`
- `jacsnpm/examples/mcp.sse.server.js`
- `jacsnpm/examples/mcp.sse.client.js`

## When To Use LangChain Instead

Choose [LangChain.js Integration](langchain.md) instead when:

- the model and tools already live in the same Node.js process
- you only need signed tool outputs, not an MCP boundary
- you do not need other MCP clients to connect
