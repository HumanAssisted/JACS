# MCP Integration (Node.js)

{{#include ../_snippets/node-registry-status.md}}

MCP is the primary integration for external model clients. For the portable
server, install `jacs-cli` and run `jacs mcp`; it starts in verify-only mode.
See the [current MCP guide](https://humanassisted.github.io/JACS/mcp-quickstart.html). The separate native compatibility
server is `jacs-compat mcp` from `jacs-cli-compat`.

Inside a Node application, choose between signed tool results on ordinary
MCP and the JACS transport extension. Signing an output does not authenticate
its recipient or authorize a tool call.

```bash
npm install @hai.ai/jacs @modelcontextprotocol/sdk
```

## Signed tool results on ordinary MCP

This ES module (`server.mjs`) registers a read-only echo tool that signs its
result. The SDK uses request schemas, not string method names, for handlers:

```javascript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart({
  name: 'echo-server', domain: 'mcp.local',
  configPath: './server/jacs.config.json',
});
const server = new Server(
  { name: 'signed-echo', version: '1.0.0' },
  { capabilities: { tools: {} } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: 'echo', description: 'Return signed echo data',
    inputSchema: {
      type: 'object', properties: { message: { type: 'string' } },
      required: ['message'], additionalProperties: false,
    },
  }],
}));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== 'echo') throw new Error('Unknown tool');
  const message = request.params.arguments?.message;
  if (typeof message !== 'string') throw new Error('message must be a string');
  const signed = await client.signMessage({ echo: message });
  return { content: [{ type: 'text', text: signed.raw }] };
});
await server.connect(new StdioServerTransport());
```

An ordinary MCP client can call this tool. Its relying application must verify
the returned document against its own trusted keys before using the contents.
Keep stdio diagnostics on stderr; stdout carries protocol messages only.

## Signed transport between JACS peers

Both peers must use the JACS transport wrapper. This is a local-only extension,
not a transparent way to connect arbitrary MCP clients. The implementation
rejects `localOnly: false`.

Provision each peer's identity and verification key through a trusted channel
before connecting. Set one exact `expectedPeerAgentId`, or an intentional
`allowedPeerAgentIds` allowlist, on **each** wrapper. A missing policy rejects
incoming authenticated messages. An optional `expectedPeerPublicKeyHash`
additionally pins the key for one exact peer.

Replace the final connection in the server above with:

```javascript
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const expectedPeerAgentId = process.env.JACS_EXPECTED_CLIENT_ID;
if (!expectedPeerAgentId) throw new Error('Configure the trusted client agent ID');
const transport = createJACSTransportProxy(
  new StdioServerTransport(), client, 'server', { expectedPeerAgentId },
);
await server.connect(transport);
```

The matching client wraps its `StdioClientTransport` the same way, using role
`'client'` and the trusted **server** ID. Use separate configuration directories
for server and client so quickstart does not reload the same identity. Load
verification keys into the local trust/key store before starting; these options
select an allowed identity, they do not fetch its key.

When only an existing config path is available:

```javascript
import { createJACSTransportProxyAsync } from '@hai.ai/jacs/mcp';

const transport = await createJACSTransportProxyAsync(
  baseTransport, './client/jacs.config.json', 'client',
  { expectedPeerAgentId: trustedServerId },
);
```

The synchronous factory takes a loaded `JacsClient` or `JacsAgent`, never a
config path. Signing, signature checks, peer checks and message dispatch fail
closed by default. Do not use `allowUnsignedFallback` or
`dangerouslyAllowAnyValidSigner` when authenticated peer identity is required.
Signatures provide integrity and key possession, not encryption. Application
permissions and replay policy remain separate from signature validity.

## Registering compatibility tools

`registerJacsTools(server, client)` installs the Node compatibility tool list
and SDK handlers on a low-level `Server`. It replaces the list/call handlers,
so do not combine it with the echo handlers above. The helper includes signing,
agreement and trust-store mutations as well as inspection; it does not inherit
the portable server's verify-only profile. Expose only operations authorized
for your callers.

For a selected tool list, use `getJacsMcpToolDefinitions()` and
`handleJacsMcpToolCall(client, name, args)` behind your own SDK schema handlers
and allowlist. Some setup/registry entries are stubs; listing an operation
does not establish that it implements the full Rust server contract.

For a model already running inside Node, see [LangChain.js](langchain.md) or
[Vercel AI SDK](vercel-ai.md). For protocol-wide concepts, see
[the native MCP guide](../integrations/mcp.md).
