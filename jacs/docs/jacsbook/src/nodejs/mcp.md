# Model Context Protocol (MCP) Integration

JACS provides native integration with the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), enabling secure agent communication within AI systems. JACS uses a transport proxy pattern that wraps any MCP transport with cryptographic signing and verification.

## What is MCP?

Model Context Protocol is a standard for AI models to securely access external tools, data, and services. JACS enhances MCP by adding:

- **Cryptographic verification** of all messages
- **Agent identity** for all operations
- **Transparent encryption** of MCP JSON-RPC traffic
- **Audit trails** of all MCP interactions

## How JACS MCP Works

JACS provides a **transport proxy** that sits between your MCP server/client and the underlying transport (STDIO, SSE, WebSocket). The proxy:

1. **Outgoing messages**: Signs JSON-RPC messages with the JACS agent's key using `signRequest()`
2. **Incoming messages**: Verifies signatures using `verifyResponse()` and extracts the payload
3. **Fallback**: If verification fails, passes messages through as plain JSON (graceful degradation)

## Quick Start

### Basic MCP Server with JACS

```javascript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJACSTransportProxy } from 'jacsnpm/mcp';
import { z } from 'zod';

const JACS_CONFIG_PATH = "./jacs.config.json";

async function main() {
  // Create the base STDIO transport
  const baseTransport = new StdioServerTransport();

  // Wrap with JACS encryption
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    JACS_CONFIG_PATH,
    "server"
  );

  // Create MCP server
  const server = new McpServer({
    name: "my-jacs-server",
    version: "1.0.0"
  });

  // Register tools
  server.tool("add", {
    a: z.number().describe("First number"),
    b: z.number().describe("Second number")
  }, async ({ a, b }) => {
    return { content: [{ type: "text", text: `${a} + ${b} = ${a + b}` }] };
  });

  // Connect with JACS encryption
  await server.connect(secureTransport);
  console.error("JACS MCP Server running with encryption enabled");
}

main();
```

### MCP Client with JACS

```javascript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createJACSTransportProxy } from 'jacsnpm/mcp';

const JACS_CONFIG_PATH = "./jacs.config.json";

async function main() {
  // Create base transport to connect to MCP server
  const baseTransport = new StdioClientTransport({
    command: 'node',
    args: ['my-jacs-server.js']
  });

  // Wrap with JACS encryption
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    JACS_CONFIG_PATH,
    "client"
  );

  // Create MCP client
  const client = new Client({
    name: "my-jacs-client",
    version: "1.0.0"
  }, {
    capabilities: {
      tools: {}
    }
  });

  // Connect with JACS encryption
  await client.connect(secureTransport);

  // List available tools
  const tools = await client.listTools();
  console.log('Available tools:', tools.tools.map(t => t.name));

  // Call a tool (message will be JACS-signed)
  const result = await client.callTool({
    name: "add",
    arguments: { a: 5, b: 3 }
  });

  console.log('Result:', result.content);
}

main();
```

## API Reference

### JACSTransportProxy

The main class that wraps MCP transports with JACS encryption.

```javascript
import { JACSTransportProxy } from 'jacsnpm/mcp';

const proxy = new JACSTransportProxy(
  transport,      // Any MCP transport (Stdio, SSE, WebSocket)
  role,           // "server" or "client"
  jacsConfigPath  // Path to jacs.config.json
);
```

### createJACSTransportProxy

Factory function for creating a transport proxy.

```javascript
import { createJACSTransportProxy } from 'jacsnpm/mcp';

const secureTransport = createJACSTransportProxy(
  baseTransport,    // The underlying MCP transport
  configPath,       // Path to jacs.config.json
  role              // "server" or "client"
);
```

### createJACSTransportProxyAsync

Async factory that waits for JACS to be fully loaded before returning.

```javascript
import { createJACSTransportProxyAsync } from 'jacsnpm/mcp';

const secureTransport = await createJACSTransportProxyAsync(
  baseTransport,
  configPath,
  role
);
```

## Transport Options

### STDIO Transport

Best for CLI tools and subprocess communication:

```javascript
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJACSTransportProxy } from 'jacsnpm/mcp';

const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(
  baseTransport,
  "./jacs.config.json",
  "server"
);
```

**Important**: When using STDIO transport, all debug logging goes to `stderr` to keep `stdout` clean for JSON-RPC messages.

### SSE Transport (HTTP)

For web-based MCP servers:

```javascript
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { createJACSTransportProxy } from 'jacsnpm/mcp';
import express from 'express';

const app = express();

app.get('/sse', (req, res) => {
  const baseTransport = new SSEServerTransport('/messages', res);
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    "./jacs.config.json",
    "server"
  );

  // Connect your MCP server to secureTransport
  server.connect(secureTransport);
});

// Handle POST messages with JACS decryption
app.post('/messages', express.text(), async (req, res) => {
  await secureTransport.handlePostMessage(req, res, req.body);
});

app.listen(3000);
```

## Configuration

### JACS Config File

Create a `jacs.config.json` for your MCP server/client:

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

### Environment Variables

Enable debug logging (not recommended for STDIO):

```bash
export JACS_MCP_DEBUG=true
```

## How Messages Are Signed

### Outgoing Messages

When the MCP SDK sends a message, the proxy intercepts it and:

1. Serializes the JSON-RPC message
2. Calls `jacs.signRequest(message)` to create a JACS artifact
3. Sends the signed artifact to the transport

```javascript
// Original MCP message
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": { "name": "add", "arguments": { "a": 5, "b": 3 } }
}

// Becomes a JACS-signed artifact with jacsId, jacsSignature, etc.
```

### Incoming Messages

When the transport receives a message, the proxy:

1. Attempts to verify it as a JACS artifact using `jacs.verifyResponse()`
2. If valid, extracts the original JSON-RPC payload
3. If not valid JACS, parses as plain JSON (fallback mode)
4. Passes the clean message to the MCP SDK

## Complete Example

### Server (mcp.server.js)

```javascript
#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJACSTransportProxy } from 'jacsnpm/mcp';
import { z } from 'zod';

async function main() {
  console.error("JACS MCP Server starting...");

  // Create transport with JACS encryption
  const baseTransport = new StdioServerTransport();
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    "./jacs.server.config.json",
    "server"
  );

  // Create MCP server
  const server = new McpServer({
    name: "jacs-demo-server",
    version: "1.0.0"
  });

  // Register tools
  server.tool("echo", {
    message: z.string().describe("Message to echo")
  }, async ({ message }) => {
    console.error(`Echo called with: ${message}`);
    return { content: [{ type: "text", text: `Echo: ${message}` }] };
  });

  server.tool("add", {
    a: z.number().describe("First number"),
    b: z.number().describe("Second number")
  }, async ({ a, b }) => {
    console.error(`Add called with: ${a}, ${b}`);
    return { content: [{ type: "text", text: `Result: ${a + b}` }] };
  });

  // Register resources
  server.resource(
    "server-info",
    "info://server",
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: "JACS-secured MCP Server",
        mimeType: "text/plain"
      }]
    })
  );

  // Connect
  await server.connect(secureTransport);
  console.error("Server running with JACS encryption");
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
```

### Client (mcp.client.js)

```javascript
#!/usr/bin/env node
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createJACSTransportProxy } from 'jacsnpm/mcp';

async function main() {
  console.log("JACS MCP Client starting...");

  // Connect to the server
  const baseTransport = new StdioClientTransport({
    command: 'node',
    args: ['mcp.server.js']
  });

  const secureTransport = createJACSTransportProxy(
    baseTransport,
    "./jacs.client.config.json",
    "client"
  );

  const client = new Client({
    name: "jacs-demo-client",
    version: "1.0.0"
  }, {
    capabilities: { tools: {} }
  });

  await client.connect(secureTransport);
  console.log("Connected to JACS MCP Server");

  // List tools
  const tools = await client.listTools();
  console.log("Available tools:", tools.tools.map(t => t.name));

  // Call echo tool
  const echoResult = await client.callTool({
    name: "echo",
    arguments: { message: "Hello, JACS!" }
  });
  console.log("Echo result:", echoResult.content[0].text);

  // Call add tool
  const addResult = await client.callTool({
    name: "add",
    arguments: { a: 10, b: 20 }
  });
  console.log("Add result:", addResult.content[0].text);

  await client.close();
}

main().catch(console.error);
```

## Security Considerations

### Message Verification

All JACS-signed messages include:
- `jacsId` - Unique document identifier
- `jacsVersion` - Version tracking
- `jacsSignature` - Cryptographic signature
- `jacsHash` - Content hash for integrity

### Passthrough Mode

If JACS cannot verify an incoming message, it falls back to plain JSON parsing. This allows:
- Gradual migration to JACS-secured communication
- Interoperability with non-JACS MCP clients/servers

To require JACS verification (no fallback), implement custom validation in your tools.

### Key Management

Each MCP server and client needs its own JACS agent with:
- Unique agent ID
- Private/public key pair
- Configuration file

## Debugging

### Enable Debug Logging

```bash
export JACS_MCP_DEBUG=true
```

This outputs detailed logs about message signing and verification.

### STDIO Debug Note

For STDIO transports, debug logs go to `stderr` to prevent contaminating the JSON-RPC stream on `stdout`.

### Common Issues

**"JACS not operational"**: Check that your config file path is correct and the agent is properly initialized.

**Verification failures**: Ensure both server and client are using compatible JACS versions and valid keys.

**Empty responses**: The proxy removes null values from messages to prevent MCP schema validation issues.

## Next Steps

- [HTTP Server](http.md) - Create HTTP APIs with JACS
- [Express Middleware](express.md) - Integrate with Express.js
- [API Reference](api.md) - Complete API documentation
