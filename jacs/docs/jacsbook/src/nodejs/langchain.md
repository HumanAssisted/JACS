# LangChain.js Integration

Use the LangChain.js adapter when the model already runs inside your Node.js app and you want provenance at the tool boundary.

## Choose The Pattern

### Give The Agent JACS Tools

Use `createJacsTools()` when the model should explicitly ask to sign, verify, inspect trust, or create agreements.

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { createJacsTools } from '@hai.ai/jacs/langchain';

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});

const jacsTools = createJacsTools({ client });
const llmWithTools = model.bindTools([...myTools, ...jacsTools]);
```

The tool set includes 14 tools:

- `jacs_sign`
- `jacs_verify`
- `jacs_create_agreement`
- `jacs_sign_agreement`
- `jacs_check_agreement`
- `jacs_verify_self`
- `jacs_trust_agent`
- `jacs_trust_agent_with_key`
- `jacs_list_trusted`
- `jacs_is_trusted`
- `jacs_share_public_key`
- `jacs_share_agent`
- `jacs_audit`
- `jacs_agent_info`

### Auto-Sign Existing Tools

Use this when the model should keep using your existing tool set but every result needs a signature.

Wrap one tool:

```typescript
import { signedTool } from '@hai.ai/jacs/langchain';

const signed = signedTool(mySearchTool, { client });
```

Wrap a LangGraph `ToolNode`:

```typescript
import { jacsToolNode } from '@hai.ai/jacs/langchain';

const node = jacsToolNode([tool1, tool2], { client });
```

For custom graph logic:

```typescript
import { jacsWrapToolCall } from '@hai.ai/jacs/langchain';

const wrapToolCall = jacsWrapToolCall({ client });
```

## Install

```bash
npm install @hai.ai/jacs @langchain/core
npm install @langchain/langgraph
```

`@langchain/langgraph` is only required for `jacsToolNode()`.

## Strict Mode

Pass `strict: true` when you want wrapper failures to throw instead of returning error-shaped output:

```typescript
const jacsTools = createJacsTools({ client, strict: true });
```

## Examples In This Repo

- `jacsnpm/examples/langchain/basic-agent.ts`
- `jacsnpm/examples/langchain/signing-callback.ts`

## When To Use MCP Instead

Choose [Node.js MCP Integration](mcp.md) instead when:

- the model is outside your process and connects over MCP
- you want a shared MCP server usable by multiple clients
- you need transport-level signing in addition to signed tool outputs
