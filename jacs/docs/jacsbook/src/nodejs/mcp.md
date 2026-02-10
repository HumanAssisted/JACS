# Model Context Protocol (MCP) Integration

JACS provides a transport proxy that wraps any MCP transport with cryptographic signing and verification. Every JSON-RPC message is signed outgoing and verified incoming -- transparently.

## 5-Minute Quickstart

### 1. Install

```bash
npm install @hai.ai/jacs @modelcontextprotocol/sdk
```

### 2. Create a JACS client

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart();
```

### 3. Wrap your MCP transport

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const transport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(transport, client, 'server');

const server = new McpServer({ name: 'my-server', version: '1.0.0' });
await server.connect(secureTransport);
```

Every JSON-RPC message is now signed outgoing and verified incoming.

---

## How It Works

The `JACSTransportProxy` sits between your MCP server/client and the underlying transport (STDIO, WebSocket, etc.):

1. **Outgoing**: Signs JSON-RPC messages with `signRequest()`
2. **Incoming**: Verifies signatures with `verifyResponse()`, extracts the payload
3. **Fallback**: If verification fails, passes messages through as plain JSON (graceful degradation)

## Quick Start

### MCP Server with JACS

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { JacsClient } from '@hai.ai/jacs/client';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';
import { z } from 'zod';

const client = await JacsClient.quickstart();
const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(baseTransport, client, "server");

const server = new McpServer({ name: "my-server", version: "1.0.0" });

server.tool("add", {
  a: z.number(),
  b: z.number(),
}, async ({ a, b }) => {
  return { content: [{ type: "text", text: `${a + b}` }] };
});

await server.connect(secureTransport);
```

### MCP Client with JACS

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { JacsClient } from '@hai.ai/jacs/client';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const client = await JacsClient.quickstart();
const baseTransport = new StdioClientTransport({
  command: 'node', args: ['my-server.js']
});
const secureTransport = createJACSTransportProxy(baseTransport, client, "client");

const mcpClient = new Client(
  { name: "my-client", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

await mcpClient.connect(secureTransport);

const result = await mcpClient.callTool({ name: "add", arguments: { a: 5, b: 3 } });
console.log(result.content[0].text); // "8"
```

## API Reference

### JACSTransportProxy

The constructor accepts a `JacsClient` or `JacsAgent` instance (not a config path):

```typescript
import { JACSTransportProxy } from '@hai.ai/jacs/mcp';

const proxy = new JACSTransportProxy(
  transport,        // Any MCP transport (STDIO, WebSocket, etc.)
  clientOrAgent,    // JacsClient or JacsAgent instance
  role,             // "server" or "client" (default: "server")
);
```

### createJACSTransportProxy

Synchronous factory -- use when you already have a loaded client/agent:

```typescript
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const secureTransport = createJACSTransportProxy(
  baseTransport,     // The underlying MCP transport
  clientOrAgent,     // JacsClient or JacsAgent
  role,              // "server" or "client"
);
```

### createJACSTransportProxyAsync

Async factory -- loads a `JacsAgent` from a config file:

```typescript
import { createJACSTransportProxyAsync } from '@hai.ai/jacs/mcp';

const secureTransport = await createJACSTransportProxyAsync(
  baseTransport,
  "./jacs.config.json",
  "server",
);
```

## MCP Tool Registration

Register all JACS operations as MCP tools on your server with a single call. This mirrors the Rust `jacs-mcp` server's tool suite, giving LLMs full access to JACS signing, verification, agreements, trust, and audit.

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { JacsClient } from '@hai.ai/jacs/client';
import { registerJacsTools } from '@hai.ai/jacs/mcp';

const server = new Server(
  { name: 'my-jacs-server', version: '1.0.0' },
  { capabilities: { tools: {} } },
);

const client = await JacsClient.quickstart();
registerJacsTools(server, client);

const transport = new StdioServerTransport();
await server.connect(transport);
```

This registers 17 tools:

| Tool | Description |
|------|-------------|
| `jacs_sign_document` | Sign arbitrary JSON data |
| `jacs_verify_document` | Verify a signed document |
| `jacs_verify_by_id` | Verify by storage ID |
| `jacs_create_agreement` | Create multi-party agreement |
| `jacs_sign_agreement` | Sign an agreement |
| `jacs_check_agreement` | Check agreement status |
| `jacs_audit` | Run security audit |
| `jacs_sign_file` | Sign a file |
| `jacs_verify_self` | Verify agent integrity |
| `jacs_agent_info` | Get agent metadata |
| `fetch_agent_key` | Fetch key from HAI |
| `jacs_register` | Register with HAI.ai |
| `jacs_setup_instructions` | DNS/well-known setup |
| `jacs_trust_agent` | Add to trust store |
| `jacs_list_trusted` | List trusted agents |
| `jacs_is_trusted` | Check trust status |
| `jacs_reencrypt_key` | Re-encrypt private key |

For custom integration, use `getJacsMcpToolDefinitions()` and `handleJacsMcpToolCall()` separately:

```typescript
import { getJacsMcpToolDefinitions, handleJacsMcpToolCall } from '@hai.ai/jacs/mcp';

const tools = getJacsMcpToolDefinitions();
const result = await handleJacsMcpToolCall(client, 'jacs_sign_document', { data: '{"action":"approve"}' });
```

## STDIO Transport

Best for CLI tools and subprocess communication:

```typescript
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(baseTransport, client, "server");
```

Debug logs go to `stderr` to keep `stdout` clean for JSON-RPC messages.

## Configuration

### Environment Variables

```bash
export JACS_MCP_DEBUG=true   # Enable debug logging (not recommended for STDIO)
```

### JACS Config File

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_default_storage": "fs",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_id_and_version": "agent-uuid:version-uuid"
}
```

## Security

### Message Signing

All JACS-signed messages include `jacsId`, `jacsVersion`, `jacsSignature`, and `jacsHash` for integrity and identity verification.

### Passthrough Mode

If JACS cannot verify an incoming message, it falls back to plain JSON parsing. This allows gradual migration and interoperability with non-JACS MCP clients/servers.

### Key Management

Each MCP server and client needs its own JACS agent with a unique agent ID and key pair.

## Debugging

**"JACS not operational"**: Check config file path and agent initialization.

**Verification failures**: Ensure both sides use compatible JACS versions and valid keys.

**Empty responses**: The proxy removes null values from messages to prevent MCP schema validation issues.

## Next Steps

- [LangChain.js](langchain.md) - Full JACS toolkit for LangChain agents
- [Express Middleware](express.md) - HTTP API signing
- [Vercel AI SDK](vercel-ai.md) - AI model provenance
- [API Reference](api.md) - Complete API documentation
