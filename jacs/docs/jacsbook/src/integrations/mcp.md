# MCP Overview

This is the cross-language overview of JACS + MCP integration. For language-specific details, see:
- [Node.js MCP Integration](../nodejs/mcp.md) -- transport proxy, tool registration, API reference
- [Python MCP Integration](../python/mcp.md) -- JACSMCPServer, JACSMCPClient, FastMCP middleware

JACS provides comprehensive integration with the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), enabling cryptographically signed and verified communication between AI agents and MCP servers.

## What is MCP?

Model Context Protocol is an open standard created by Anthropic for AI models to securely access external tools, data, and services. MCP defines:

- **Tools**: Functions that AI models can call
- **Resources**: Data sources that models can read
- **Prompts**: Pre-defined prompt templates
- **Transports**: Communication channels (STDIO, SSE, WebSocket)

## Why JACS + MCP?

JACS enhances MCP by adding a security layer that standard MCP lacks:

| Feature | Standard MCP | JACS MCP |
|---------|-------------|----------|
| Message Signing | No | Yes |
| Identity Verification | No | Yes |
| Tamper Detection | No | Yes |
| Audit Trail | No | Yes |
| Non-Repudiation | No | Yes |

This makes JACS MCP suitable for:
- Multi-agent systems requiring trust
- Financial and legal AI applications
- Healthcare AI systems
- Enterprise deployments
- Any scenario where message authenticity matters

## Architecture

JACS uses a **transport proxy pattern** that wraps any MCP transport with cryptographic signing and verification:

```
┌─────────────────────────────────────────────────────────────┐
│                      MCP Application                         │
├─────────────────────────────────────────────────────────────┤
│                       MCP SDK                                │
├─────────────────────────────────────────────────────────────┤
│                  JACS Transport Proxy                        │
│  ┌─────────────┐                    ┌──────────────┐        │
│  │ Outgoing:   │                    │ Incoming:    │        │
│  │ signRequest │                    │ verifyResp   │        │
│  └─────────────┘                    └──────────────┘        │
├─────────────────────────────────────────────────────────────┤
│               Underlying Transport                           │
│           (STDIO / SSE / WebSocket)                         │
└─────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Outgoing Messages**: The proxy intercepts JSON-RPC messages and signs them with the agent's private key
2. **Incoming Messages**: The proxy verifies signatures before passing messages to the application
3. **Graceful Fallback**: If verification fails, messages can be passed through as plain JSON for interoperability

## Transport Interceptors (Infrastructure Layer)

JACS MCP is not just a set of tools -- it is **middleware-level infrastructure** that wraps any MCP transport with transparent cryptographic signing and verification. Every JSON-RPC message flowing through the transport is signed on send and verified on receive, with zero changes to your application code.

### Python: `JACSMCPClient` and `JACSMCPServer`

These are factory functions (not classes) that return patched FastMCP objects with JACS interceptors wired in.

**`JACSMCPClient(url, config_path, strict=False)`** -- Wraps a FastMCP `SSETransport` with send/receive interceptors:

```python
from jacs.mcp import JACSMCPClient

# Every outgoing JSON-RPC message is signed with agent.sign_request()
# Every incoming JSON-RPC message is verified with agent.verify_response()
client = JACSMCPClient("http://localhost:8000/sse", "./jacs.config.json")

async with client:
    # This tool call is signed transparently
    result = await client.call_tool("analyze", {"text": "hello"})
```

Internally, `JACSMCPClient` monkey-patches the SSE transport's `send` and `receive` methods:

- **`intercepted_send`**: calls `agent.sign_request(message.root)` on every outgoing `JSONRPCMessage`
- **`intercepted_receive`**: calls `agent.verify_response(json.dumps(message.root))` on every incoming message

**`JACSMCPServer(mcp_server, config_path, strict=False)`** -- Wraps a FastMCP server's SSE app with Starlette HTTP middleware:

```python
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP

mcp = FastMCP("My Server")

@mcp.tool()
def hello(name: str) -> str:
    return f"Hello, {name}!"

# Wrap the server -- all /messages/ requests are verified,
# all JSON responses are signed
mcp = JACSMCPServer(mcp, "./jacs.config.json")
```

The server middleware intercepts at the HTTP level:
- **Inbound**: reads request body on `/messages/` endpoints, calls `agent.verify_response()` to validate the sender's signature
- **Outbound**: collects the response body stream, calls `agent.sign_request()` on JSON responses before returning them

### Strict Mode

Both `JACSMCPClient` and `JACSMCPServer` support `strict=True` (or `JACS_STRICT_MODE=true` env var). In strict mode, if the JACS config cannot be loaded, the transport **refuses to start** instead of falling back to unsigned communication.

```python
# Fail-fast: do not allow unsigned transport
client = JACSMCPClient(url, config_path, strict=True)
```

### Additional Python APIs

| API | Description |
|-----|-------------|
| `JacsSSETransport(url)` | SSE transport wrapper using module-level `simple.*` API |
| `create_jacs_mcp_server(name, config_path)` | One-liner: creates FastMCP + loads agent + wires middleware |
| `jacs_tool` | Decorator that signs individual tool responses |
| `jacs_middleware()` | Standalone Starlette middleware factory using `simple.*` globals |
| `jacs_call(server_url, method, **params)` | One-shot authenticated MCP call |

## Quick Start

### Node.js

```javascript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';
import { z } from 'zod';

// Create transport with JACS encryption
const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(
  baseTransport,
  "./jacs.config.json",
  "server"
);

// Create MCP server
const server = new McpServer({
  name: "my-secure-server",
  version: "1.0.0"
});

// Register tools (standard MCP API)
server.tool("add", {
  a: z.number(),
  b: z.number()
}, async ({ a, b }) => {
  return { content: [{ type: "text", text: `${a + b}` }] };
});

// Connect with JACS encryption
await server.connect(secureTransport);
```

### Python

```python
import jacs
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
import uvicorn

# Initialize JACS agent
agent = jacs.JacsAgent()
agent.load("./jacs.config.json")

# Create FastMCP server with JACS authentication
mcp = JACSMCPServer(FastMCP("Secure Server"))

@mcp.tool()
def add(a: int, b: int) -> str:
    """Add two numbers"""
    return str(a + b)

# Get ASGI app with JACS middleware
app = mcp.sse_app()

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)
```

## Language Support

JACS provides native MCP integration for both major platforms:

### Node.js (@hai.ai/jacs)

The Node.js integration uses a transport proxy pattern that works with any MCP transport:

- **STDIO**: For CLI tools and subprocess communication
- **SSE**: For web-based servers
- **WebSocket**: For bidirectional streaming

Key classes:
- `JACSTransportProxy` - Wraps any transport with signing/verification
- `createJACSTransportProxy()` - Factory function

See [Node.js MCP Integration](../nodejs/mcp.md) for complete documentation.

### Python (jacspy)

The Python integration uses middleware wrappers for FastMCP:

- **JACSMCPServer** - Wraps FastMCP servers with authentication
- **JACSMCPClient** - Wraps FastMCP clients with signing

Key classes:
- `JACSMCPServer` - Server wrapper with JACS middleware
- `JACSMCPClient` - Client wrapper with interceptors

See [Python MCP Integration](../python/mcp.md) for complete documentation.

## Message Flow

### Tool Call Example

When a client calls a tool on a JACS-enabled MCP server:

```
Client                          Server
  │                               │
  │  1. Create JSON-RPC request   │
  │  2. Sign with signRequest()   │
  │  ──────────────────────────>  │
  │                               │ 3. Verify with verifyRequest()
  │                               │ 4. Execute tool
  │                               │ 5. Sign response with signResponse()
  │  <──────────────────────────  │
  │  6. Verify with verifyResponse() │
  │  7. Extract payload           │
```

### Signed Message Structure

A JACS-signed MCP message contains:

```json
{
  "jacsId": "unique-document-id",
  "jacsVersion": "version-uuid",
  "jacsSignature": {
    "agentID": "signing-agent-id",
    "agentVersion": "agent-version",
    "date": "2024-01-15T10:30:00Z",
    "signature": "base64-signature",
    "signingAlgorithm": "ring-Ed25519"
  },
  "jacsSha256": "content-hash",
  "payload": {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": { "name": "add", "arguments": { "a": 5, "b": 3 } },
    "id": 1
  }
}
```

## Configuration

### Server Configuration

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_id_and_version": "server-agent-id:version",
  "jacs_default_storage": "fs"
}
```

### Client Configuration

Each MCP client needs its own JACS agent identity:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_id_and_version": "client-agent-id:version",
  "jacs_default_storage": "fs"
}
```

## Transports

### STDIO

Best for CLI tools and subprocess communication:

```javascript
// Node.js
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(
  baseTransport,
  "./jacs.config.json",
  "server"
);
```

**Important**: Debug logging goes to `stderr` to keep `stdout` clean for JSON-RPC.

### Server-Sent Events (SSE)

For web-based MCP servers:

```python
# Python with FastMCP
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP

mcp = JACSMCPServer(FastMCP("Web Server"))
app = mcp.sse_app()  # Returns ASGI app with JACS middleware
```

```javascript
// Node.js with Express
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from 'express';

const app = express();
app.get('/sse', (req, res) => {
  const baseTransport = new SSEServerTransport('/messages', res);
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    "./jacs.config.json",
    "server"
  );
  server.connect(secureTransport);
});
```

## Security Model

### Signing is Sacred

**CRITICAL GUIDANCE FOR AI AGENTS AND DEVELOPERS**

Signing a document or message with JACS is a **sacred, irreversible act**. When an agent signs:

1. **Permanent Commitment**: The signature creates permanent cryptographic proof that the signer attested to the content. This proof exists forever and can be verified by anyone.

2. **Non-Repudiation**: The signer cannot later deny having signed. The signature is mathematically bound to their private key.

3. **Accountability**: The signer is accountable for the content they signed. In multi-agent systems, signatures establish trust chains and responsibility.

4. **Irreversibility**: There is no "unsign" operation. Once signed, the commitment exists permanently.

**Before signing any document, message, or agreement:**
- Read and understand the complete content
- Verify the content represents your actual intent
- Confirm you have authority to make this commitment
- Understand the implications of your signature

**For AI agents**: Do not sign automatically or without verification. Signing carelessly can:
- Create binding commitments you didn't intend
- Establish false audit trails
- Damage trust relationships with other agents
- Create legal or ethical liability

**For MCP tool implementations**: When exposing signing capabilities as tools, include appropriate warnings and consider requiring explicit confirmation.

### What Gets Signed

- All JSON-RPC requests and responses
- Tool calls and results
- Resource requests and data
- Prompt requests and templates

### What Gets Verified

- Agent identity (agentID)
- Message integrity (jacsSha256)
- Signature validity (jacsSignature)
- Optional: DNS-based identity verification

### Passthrough Mode

For interoperability with non-JACS MCP systems, the proxy can fall back to plain JSON:

1. Try to verify as JACS artifact
2. If verification fails, parse as plain JSON
3. Pass clean message to application

To enforce JACS-only communication, implement custom validation in your tools.

## Debugging

### Enable Debug Logging

```bash
# Node.js
export JACS_MCP_DEBUG=true

# Python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "JACS not operational" | Config path incorrect | Verify config file path |
| Verification failures | Incompatible keys | Ensure matching key algorithms |
| Empty responses | Null value handling | Check message serialization |
| Connection timeouts | Network issues | Verify server is running |

## Best Practices

### 1. Separate Keys for Server and Client

```
project/
├── server/
│   ├── jacs.config.json
│   └── jacs_keys/
│       ├── private.pem
│       └── public.pem
└── client/
    ├── jacs.config.json
    └── jacs_keys/
        ├── private.pem
        └── public.pem
```

### 2. Use TLS for Network Transports

```python
# Use HTTPS for SSE
client = JACSMCPClient("https://server.example.com/sse")
```

### 3. Implement Key Rotation

Update agent versions when rotating keys:

```json
{
  "jacs_agent_id_and_version": "my-agent:v2"
}
```

### 4. Log Security Events

```python
# Production logging setup
import logging

logging.getLogger("jacs").setLevel(logging.INFO)
logging.getLogger("jacs.security").setLevel(logging.WARNING)
```

## Example: Multi-Agent System

A complete example with multiple JACS-authenticated agents:

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Agent A        │     │   MCP Server     │     │   Agent B        │
│  (Data Analyst)  │────>│  (Tool Provider) │<────│  (Report Writer) │
│                  │     │                  │     │                  │
│ Signs requests   │     │ Verifies both    │     │ Signs requests   │
│ Verifies resps   │     │ Signs responses  │     │ Verifies resps   │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

Each agent has its own:
- JACS agent ID and version
- Private/public key pair
- Configuration file

The MCP server verifies requests from both agents and signs all responses.

## HAI MCP Server Tools

The `jacs-mcp` server provides built-in tools for agent operations:

### Identity & Registration Tools

| Tool | Description |
|------|-------------|
| `fetch_agent_key` | Fetch a public key from HAI's key distribution service |
| `register_agent` | Register the local agent with HAI (requires `JACS_MCP_ALLOW_REGISTRATION=true`) |
| `verify_agent` | Verify another agent's attestation level |
| `check_agent_status` | Check registration status with HAI |
| `unregister_agent` | Unregister an agent from HAI |

### Agent State Tools

These tools allow agents to sign, verify, and manage state documents (memory files, skills, plans, configs, hooks, or any document):

| Tool | Description |
|------|-------------|
| `jacs_sign_state` | Create and sign a new agent state document |
| `jacs_verify_state` | Verify an existing agent state document's signature |
| `jacs_load_state` | Load an agent state document by key |
| `jacs_update_state` | Update and re-sign an agent state document |
| `jacs_list_state` | List all agent state documents |
| `jacs_adopt_state` | Adopt an external file as a signed agent state |

All documents are stored within the JACS data directory for security. Use `state_type: "other"` for general-purpose signing of any document.

See [Agent State Schema](../schemas/agentstate.md) for full documentation.

### A2A Discovery Tools

| Tool | Description |
|------|-------------|
| `jacs_export_agent_card` | Export the local agent's A2A Agent Card |
| `jacs_generate_well_known` | Generate all `.well-known` documents for A2A discovery |
| `jacs_export_agent` | Export the full JACS agent JSON document |

### Trust Store Tools

| Tool | Description |
|------|-------------|
| `jacs_trust_agent` | Add an agent to the local trust store (self-signature verified) |
| `jacs_untrust_agent` | Remove an agent from the trust store (requires `JACS_MCP_ALLOW_UNTRUST=true`) |
| `jacs_list_trusted_agents` | List all trusted agent IDs |
| `jacs_is_trusted` | Check whether an agent is trusted |
| `jacs_get_trusted_agent` | Retrieve the full JSON document for a trusted agent |

See the [jacs-mcp README](https://github.com/HumanAssisted/JACS/tree/main/jacs-mcp) for the full 31-tool reference and [A2A Interoperability](a2a.md) for A2A-specific workflows.

## See Also

- [Node.js MCP Integration](../nodejs/mcp.md) - Node.js specific details
- [Python MCP Integration](../python/mcp.md) - Python specific details
- [A2A Interoperability](a2a.md) - A2A protocol integration and trust policies
- [A2A Quickstart](../guides/a2a-quickstart.md) - Get A2A running in minutes
- [Security Model](../advanced/security.md) - JACS security architecture
- [Cryptographic Algorithms](../advanced/crypto.md) - Signing algorithms
- [Testing](../advanced/testing.md) - Testing MCP integrations
