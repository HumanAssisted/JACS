# LangChain + JACS TypeScript Integration Examples

These examples demonstrate how to use JACS cryptographic signing with LangChain.js agents via the Model Context Protocol (MCP).

## Overview

JACS provides cryptographic signing and verification for AI agent outputs. By integrating with LangChain.js via MCP, you can:

- Sign AI agent outputs to prove their origin
- Verify that data came from a specific trusted agent
- Create multi-party agreements requiring multiple agent signatures
- Maintain audit trails of signed interactions

## Prerequisites

1. **Install dependencies:**

```bash
npm install
```

2. **Set up a JACS agent:**

```bash
# Create a new agent in this directory
cd examples/langchain
npx jacs init
npx jacs create

# Or set the config path if you have an existing agent
export JACS_CONFIG=./path/to/jacs.config.json
```

3. **Set up your LLM API key:**

```bash
# For Anthropic Claude
export ANTHROPIC_API_KEY=your-key-here

# For OpenAI (if using OpenAI models)
export OPENAI_API_KEY=your-key-here
```

## Examples

### 1. Basic Agent (`basic-agent.ts`)

Demonstrates connecting a LangChain.js agent to the JACS MCP server to use signing and verification tools.

```bash
# Run with tsx
npx tsx basic-agent.ts
```

The agent can:
- Sign messages/data with `sign_data`
- Verify signatures with `verify_data`
- Get agent info with `agent_info`
- Check agent integrity via self-verification

### 2. Signing Callback (`signing-callback.ts`)

Demonstrates using LangGraph.js with a custom callback that automatically signs all agent outputs.

```bash
npx tsx signing-callback.ts
```

Features:
- `JACSSigningCallback` - Automatically signs tool outputs
- `SignedOutputsAuditTrail` - Maintains a log of all signed outputs
- TypeScript type safety throughout

## Architecture

```
+-------------------+      MCP Protocol       +------------------+
|   LangChain.js    | <-------------------->  |   JACS MCP       |
|   Agent           |                         |   Server         |
+-------------------+                         +------------------+
        |                                             |
        | Uses tools                                  | Uses
        v                                             v
+-------------------+                         +------------------+
| sign_data         |                         |   JACS Simple    |
| verify_data       |                         |   API            |
| agent_info        |                         +------------------+
| createAgreement   |                                 |
+-------------------+                                 v
                                              +------------------+
                                              |   Cryptographic  |
                                              |   Keys           |
                                              +------------------+
```

## Use Cases

### Provenance Tracking

Sign all AI-generated content to prove it came from a specific agent:

```typescript
const result = await agent.invoke({
  messages: [{ role: "user", content: "Generate a report" }]
});
// Use callback to automatically sign the result
```

### Multi-Agent Agreements

Create agreements requiring multiple agents to sign:

```typescript
// Agent 1 creates the agreement
const agreement = await jacs.createAgreement(
  { proposal: "Merge codebases" },
  ["agent-1-uuid", "agent-2-uuid"],
  "Do you approve?"
);

// Agent 2 signs it
const signed = await jacs.signAgreement(agreement);

// Check status
const status = jacs.checkAgreement(signed);
console.log(`Complete: ${status.complete}`);
```

### Audit Trails

Maintain cryptographically verifiable audit trails:

```typescript
const callback = new JACSSigningCallback();

// After interactions
for (const signedOutput of callback.auditTrail.getAll()) {
  console.log(`Tool: ${signedOutput.toolName}`);
  console.log(`Document ID: ${signedOutput.documentId}`);
  console.log(`Signed at: ${signedOutput.timestamp}`);
}
```

## TypeScript Configuration

This project uses ES modules. The examples require:

- Node.js 18+ (for native fetch)
- tsx for running TypeScript directly

See `tsconfig.json` for the full configuration.

## Troubleshooting

### "No agent loaded" error

Make sure you have a valid `jacs.config.json` in the current directory or set `JACS_CONFIG`.

### MCP connection failed

Ensure the JACS MCP server is available. The examples use stdio transport to spawn the server automatically.

### Signature verification failed

Ensure both the signer and verifier have access to the same trust store, or that the verifier has added the signer's agent to their trust store.

### TypeScript errors

Make sure you have the correct versions of dependencies and that `tsconfig.json` is properly configured.
