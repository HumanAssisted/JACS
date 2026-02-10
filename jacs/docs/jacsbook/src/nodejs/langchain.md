# LangChain.js Integration

JACS provides two integration patterns for LangChain.js:

1. **Full toolkit** -- expose all JACS operations as LangChain tools your agent can call
2. **Auto-signing wrappers** -- transparently sign existing tool outputs

## Full Toolkit

`createJacsTools()` returns an array of LangChain `DynamicStructuredTool` instances wrapping the full JacsClient API. Bind these to your LLM so the agent can sign, verify, create agreements, manage trust, and audit -- all as part of its reasoning.

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { createJacsTools } from '@hai.ai/jacs/langchain';

const client = await JacsClient.quickstart();
const jacsTools = createJacsTools({ client });

// Combine with your own tools and bind to an LLM
const allTools = [...myTools, ...jacsTools];
const llmWithTools = model.bindTools(allTools);
```

### Available Tools

| Tool | Description |
|------|-------------|
| `jacs_sign` | Sign arbitrary JSON data with cryptographic provenance |
| `jacs_verify` | Verify a signed document |
| `jacs_create_agreement` | Create a multi-party agreement |
| `jacs_sign_agreement` | Sign an existing agreement |
| `jacs_check_agreement` | Check agreement status (signatures, completeness) |
| `jacs_verify_self` | Verify this agent's integrity |
| `jacs_trust_agent` | Add an agent to the local trust store |
| `jacs_list_trusted` | List all trusted agent IDs |
| `jacs_is_trusted` | Check if a specific agent is trusted |
| `jacs_audit` | Run a security audit |
| `jacs_agent_info` | Get agent ID, name, and status |

### Strict Mode

Pass `strict: true` to make tools throw on errors instead of returning error JSON:

```typescript
const tools = createJacsTools({ client, strict: true });
```

## Auto-Signing Wrappers

### signedTool

Wraps any LangChain `BaseTool` so its output is automatically signed:

```typescript
import { signedTool } from '@hai.ai/jacs/langchain';

const signed = signedTool(mySearchTool, { client });
const result = await signed.invoke({ query: 'hello' }); // result is JACS-signed
```

### jacsToolNode (LangGraph)

Creates a LangGraph `ToolNode` where every tool's output is signed:

```typescript
import { jacsToolNode } from '@hai.ai/jacs/langchain';

const node = jacsToolNode([tool1, tool2], { client });
```

Requires `@langchain/langgraph`.

### jacsWrapToolCall

Returns an async wrapper for manual tool execution in custom LangGraph workflows:

```typescript
import { jacsWrapToolCall } from '@hai.ai/jacs/langchain';

const wrapFn = jacsWrapToolCall({ client });
// Use in custom graph: const result = await wrapFn(toolCall, runnable);
```

## Installation

```bash
npm install @hai.ai/jacs @langchain/core
# Optional for jacsToolNode:
npm install @langchain/langgraph
```

All `@langchain/*` imports are lazy -- the module can be imported without LangChain installed.

## Next Steps

- [MCP Integration](mcp.md) -- Full JACS tool suite for MCP servers
- [Vercel AI SDK](vercel-ai.md) -- AI model provenance signing
- [Express Middleware](express.md) -- HTTP API signing
