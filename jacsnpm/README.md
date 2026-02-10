# JACS for Node.js

**Sign it. Prove it.**

Cryptographic signatures for AI agent outputs -- so anyone can verify who said what and whether it was changed. No server. Three lines of code. Optionally register with [HAI.ai](https://hai.ai) for cross-organization key discovery.

[Which integration should I use?](https://humanassisted.github.io/JACS/getting-started/decision-tree.html) | [Full documentation](https://humanassisted.github.io/JACS/)

**Dependencies**: The `overrides` in `package.json` for `body-parser` and `qs` are for security (CVE-2024-45590). Do not remove them without re-auditing.

## Installation

```bash
npm install @hai.ai/jacs
```

The npm package ships prebuilt native bindings for supported targets and does not compile Rust during `npm install`.

## v0.8.0: Framework Adapters

New in v0.8.0: first-class adapters for **Vercel AI SDK**, **Express**, **Koa**, **LangChain.js**, and a full **MCP tool suite**. All framework dependencies are optional peer deps — install only what you use.

### Async-First API

All NAPI operations return Promises by default. Sync variants are available with a `Sync` suffix, following the Node.js convention (like `fs.readFile` vs `fs.readFileSync`).

```javascript
// Async (default, recommended -- does not block the event loop)
const signed = await jacs.signMessage({ action: 'approve' });

// Sync (blocks event loop, use in scripts or CLI tools)
const signed = jacs.signMessageSync({ action: 'approve' });
```

## Quick Start

Zero-config -- one call to start signing:

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.quickstart();
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

`quickstart()` creates a persistent agent with keys on disk. If `./jacs.config.json` already exists, it loads it; otherwise it creates a new agent. Agent, keys, and config are saved to `./jacs_data`, `./jacs_keys`, and `./jacs.config.json`. If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure password is auto-generated and saved to `./jacs_keys/.jacs_password`. Pass `{ algorithm: 'ring-Ed25519' }` to override the default (`pq2025`).

### Advanced: Loading an existing agent

If you already have an agent (e.g., created by a previous `quickstart()` call), load it explicitly:

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.load('./jacs.config.json');

const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

## Core API

Every function that calls into NAPI has both async (default) and sync variants:

| Function | Sync Variant | Description |
|----------|-------------|-------------|
| `quickstart(options?)` | `quickstartSync(options?)` | Create a persistent agent with keys on disk |
| `create(options)` | `createSync(options)` | Create a new agent programmatically |
| `load(configPath)` | `loadSync(configPath)` | Load agent from config file |
| `verifySelf()` | `verifySelfSync()` | Verify agent's own integrity |
| `updateAgent(data)` | `updateAgentSync(data)` | Update agent document |
| `updateDocument(id, data)` | `updateDocumentSync(id, data)` | Update existing document |
| `signMessage(data)` | `signMessageSync(data)` | Sign any JSON data |
| `signFile(path, embed)` | `signFileSync(path, embed)` | Sign a file |
| `verify(doc)` | `verifySync(doc)` | Verify signed document |
| `verifyById(id)` | `verifyByIdSync(id)` | Verify by storage ID |
| `reencryptKey(old, new)` | `reencryptKeySync(old, new)` | Re-encrypt private key |
| `getSetupInstructions(domain)` | `getSetupInstructionsSync(domain)` | Get DNS/well-known setup |
| `createAgreement(doc, ids, ...)` | `createAgreementSync(doc, ids, ...)` | Create multi-party agreement |
| `signAgreement(doc)` | `signAgreementSync(doc)` | Sign an agreement |
| `checkAgreement(doc)` | `checkAgreementSync(doc)` | Check agreement status |
| `audit(options?)` | `auditSync(options?)` | Run a security audit |

Pure sync functions (no NAPI call, no suffix needed):

| Function | Description |
|----------|-------------|
| `verifyStandalone(doc, opts?)` | Verify without loading an agent |
| `getPublicKey()` | Get public key |
| `isLoaded()` | Check if agent is loaded |
| `getDnsRecord(domain, ttl?)` | Get DNS TXT record |
| `getWellKnownJson()` | Get well-known JSON |
| `trustAgent(json)` | Add agent to trust store |
| `listTrustedAgents()` | List trusted agent IDs |
| `untrustAgent(id)` | Remove from trust store |
| `isTrusted(id)` | Check if agent is trusted |
| `getTrustedAgent(id)` | Get trusted agent's JSON |
| `generateVerifyLink(doc, baseUrl?)` | Generate verification URL |

## Types

```typescript
interface SignedDocument {
  raw: string;        // Full JSON document
  documentId: string; // UUID
  agentId: string;    // Signer's ID
  timestamp: string;  // ISO 8601
}

interface VerificationResult {
  valid: boolean;
  data?: any;
  signerId: string;
  timestamp: string;
  attachments: Attachment[];
  errors: string[];
}
```

## Programmatic Agent Creation

```typescript
const jacs = require('@hai.ai/jacs/simple');

const agent = await jacs.create({
  name: 'my-agent',
  password: process.env.JACS_PRIVATE_KEY_PASSWORD,  // required
  algorithm: 'pq2025',                  // default; also: "ring-Ed25519", "RSA-PSS"
  dataDirectory: './jacs_data',
  keyDirectory: './jacs_keys',
});
console.log(`Created: ${agent.agentId}`);
```

### Verify by Document ID

```javascript
const result = await jacs.verifyById('550e8400-e29b-41d4-a716-446655440000:1');
console.log(`Valid: ${result.valid}`);
```

### Re-encrypt Private Key

```javascript
await jacs.reencryptKey('old-password-123!', 'new-Str0ng-P@ss!');
```

### Password Requirements

Passwords must be at least 8 characters and include uppercase, lowercase, a digit, and a special character.

### Algorithm Deprecation Notice

The `pq-dilithium` algorithm is deprecated. Use `pq2025` (ML-DSA-87, FIPS-204) instead. `pq-dilithium` still works but emits deprecation warnings.

## Examples

### Sign and Verify

```javascript
const jacs = require('@hai.ai/jacs/simple');

await jacs.load('./jacs.config.json');

// Sign data
const signed = await jacs.signMessage({
  action: 'transfer',
  amount: 500,
  to: 'agent-123'
});

// Later, verify received data
const result = await jacs.verify(receivedJson);
if (result.valid) {
  console.log(`Signed by: ${result.signerId}`);
  console.log(`Data: ${JSON.stringify(result.data)}`);
}
```

### Update Agent

```javascript
// Get current agent, modify, and update
const agentDoc = JSON.parse(jacs.exportAgent());
agentDoc.jacsAgentType = 'updated-service';
const updated = await jacs.updateAgent(agentDoc);
console.log('Agent updated with new version');
```

### Update Document

```javascript
// Create a document
const signed = await jacs.signMessage({ status: 'pending', amount: 100 });

// Later, update it
const doc = JSON.parse(signed.raw);
doc.content.status = 'approved';
const updated = await jacs.updateDocument(signed.documentId, doc);
console.log('Document updated with new version');
```

### File Signing

```javascript
// Reference only (stores hash)
const signed = await jacs.signFile('contract.pdf', false);

// Embed content (portable document)
const embedded = await jacs.signFile('contract.pdf', true);
```

## Framework Adapters

### Vercel AI SDK (`@hai.ai/jacs/vercel-ai`)

Sign AI model outputs with cryptographic provenance using the AI SDK's middleware pattern:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { withProvenance } from '@hai.ai/jacs/vercel-ai';
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

const client = await JacsClient.quickstart();
const model = withProvenance(openai('gpt-4o'), { client });

const { text, providerMetadata } = await generateText({ model, prompt: 'Hello!' });
console.log(providerMetadata?.jacs?.text?.documentId); // signed proof
```

Works with `generateText`, `streamText` (signs after stream completes), and tool calls. Compose with other middleware via `jacsProvenance()`.

**Peer deps**: `npm install ai @ai-sdk/provider`

### Express Middleware (`@hai.ai/jacs/express`)

Verify incoming signed requests, optionally auto-sign responses:

```typescript
import express from 'express';
import { JacsClient } from '@hai.ai/jacs/client';
import { jacsMiddleware } from '@hai.ai/jacs/express';

const client = await JacsClient.quickstart();
const app = express();
app.use(express.text({ type: 'application/json' }));
app.use(jacsMiddleware({ client, verify: true }));

app.post('/api/data', (req, res) => {
  console.log(req.jacsPayload); // verified payload
  // Manual signing via req.jacsClient:
  req.jacsClient.signMessage({ status: 'ok' }).then(signed => {
    res.type('text/plain').send(signed.raw);
  });
});
```

Options: `client`, `configPath`, `sign` (auto-sign, default false), `verify` (default true), `optional` (allow unsigned, default false). Supports Express v4 + v5.

**Peer dep**: `npm install express`

### Koa Middleware (`@hai.ai/jacs/koa`)

```typescript
import Koa from 'koa';
import { jacsKoaMiddleware } from '@hai.ai/jacs/koa';

const app = new Koa();
app.use(jacsKoaMiddleware({ client, verify: true, sign: true }));
app.use(async (ctx) => {
  console.log(ctx.state.jacsPayload); // verified
  ctx.body = { status: 'ok' };        // auto-signed when sign: true
});
```

**Peer dep**: `npm install koa`

### LangChain.js (`@hai.ai/jacs/langchain`)

Two integration patterns — full toolkit or auto-signing wrappers:

**Full toolkit** — give your LangChain agent access to all JACS operations (sign, verify, agreements, trust, audit):

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { createJacsTools } from '@hai.ai/jacs/langchain';

const client = await JacsClient.quickstart();
const jacsTools = createJacsTools({ client });

// Bind to your LLM — agent can now sign, verify, create agreements, etc.
const llm = model.bindTools([...myTools, ...jacsTools]);
```

Returns 11 tools: `jacs_sign`, `jacs_verify`, `jacs_create_agreement`, `jacs_sign_agreement`, `jacs_check_agreement`, `jacs_verify_self`, `jacs_trust_agent`, `jacs_list_trusted`, `jacs_is_trusted`, `jacs_audit`, `jacs_agent_info`.

**Auto-signing wrappers** — transparently sign existing tool outputs:

```typescript
import { signedTool, jacsToolNode } from '@hai.ai/jacs/langchain';

// Wrap a single tool
const signed = signedTool(myTool, { client });

// Or wrap all tools in a ToolNode (LangGraph)
const node = jacsToolNode([tool1, tool2], { client });
```

**Peer deps**: `npm install @langchain/core` (and optionally `@langchain/langgraph` for `jacsToolNode`)

### MCP (`@hai.ai/jacs/mcp`)

Two integration patterns — transport proxy or full tool registration:

**Transport proxy** — wrap any MCP transport with signing/verification:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const client = await JacsClient.quickstart();
const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(baseTransport, client, 'server');
```

**MCP tool registration** — add all JACS tools to your MCP server (mirrors the Rust `jacs-mcp` server):

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { JacsClient } from '@hai.ai/jacs/client';
import { registerJacsTools } from '@hai.ai/jacs/mcp';

const server = new Server({ name: 'my-server', version: '1.0.0' }, { capabilities: { tools: {} } });
const client = await JacsClient.quickstart();
registerJacsTools(server, client);
```

Registers 17 tools: signing, verification, agreements, trust store, audit, HAI integration, file signing, and more. Use `getJacsMcpToolDefinitions()` and `handleJacsMcpToolCall()` for custom integration.

**Peer dep**: `npm install @modelcontextprotocol/sdk`

### Legacy: `@hai.ai/jacs/http`

The old `JACSExpressMiddleware` and `JACSKoaMiddleware` are still available from `@hai.ai/jacs/http` for backward compatibility. New code should use `@hai.ai/jacs/express` and `@hai.ai/jacs/koa`.

## JacsClient (Instance-Based API)

`JacsClient` is the recommended API for new code. Each instance owns its own agent, so multiple clients can coexist in the same process without shared global state.

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

// Zero-config: loads or creates a persistent agent
const client = await JacsClient.quickstart({ algorithm: 'ring-Ed25519' });

const signed = await client.signMessage({ action: 'approve', amount: 100 });
const result = await client.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Ephemeral Clients

For testing or throwaway use, create an in-memory client with no files or env vars:

```typescript
const client = await JacsClient.ephemeral('ring-Ed25519');
const signed = await client.signMessage({ hello: 'world' });
const result = await client.verify(signed.raw);
```

Sync variants are also available:

```typescript
const client = JacsClient.ephemeralSync('ring-Ed25519');
const signed = client.signMessageSync({ hello: 'world' });
const result = client.verifySync(signed.raw);
```

### Multi-Party Agreements

Create agreements that require signatures from multiple agents, with optional constraints:

```typescript
const agreement = await client.createAgreement(
  { action: 'deploy', version: '2.0' },
  [agentA.agentId, agentB.agentId],
  {
    question: 'Approve deployment?',
    timeout: '2026-03-01T00:00:00Z',    // ISO 8601 deadline
    quorum: 2,                            // M-of-N signatures required
    requiredAlgorithms: ['ring-Ed25519'], // restrict signing algorithms
    minimumStrength: 'classical',         // "classical" or "post-quantum"
  },
);

// Other agents sign the agreement
const signed = await agentB.signAgreement(agreement.raw);

// Check agreement status
const status = await client.checkAgreement(signed.raw);
console.log(`Complete: ${status.complete}, Signatures: ${status.signedCount}/${status.totalRequired}`);
```

### JacsClient API

All instance methods have async (default) and sync variants:

| Method | Sync Variant | Description |
|--------|-------------|-------------|
| `JacsClient.quickstart(options?)` | `JacsClient.quickstartSync(options?)` | Load or create a persistent agent |
| `JacsClient.ephemeral(algorithm?)` | `JacsClient.ephemeralSync(algorithm?)` | Create an in-memory agent |
| `client.load(configPath?)` | `client.loadSync(configPath?)` | Load agent from config file |
| `client.create(options)` | `client.createSync(options)` | Create a new agent |
| `client.signMessage(data)` | `client.signMessageSync(data)` | Sign any JSON data |
| `client.verify(doc)` | `client.verifySync(doc)` | Verify a signed document |
| `client.verifySelf()` | `client.verifySelfSync()` | Verify agent's own integrity |
| `client.verifyById(id)` | `client.verifyByIdSync(id)` | Verify by storage ID |
| `client.signFile(path, embed?)` | `client.signFileSync(path, embed?)` | Sign a file |
| `client.createAgreement(...)` | `client.createAgreementSync(...)` | Create multi-party agreement |
| `client.signAgreement(...)` | `client.signAgreementSync(...)` | Sign an agreement |
| `client.checkAgreement(...)` | `client.checkAgreementSync(...)` | Check agreement status |
| `client.updateAgent(data)` | `client.updateAgentSync(data)` | Update agent document |
| `client.updateDocument(id, data)` | `client.updateDocumentSync(id, data)` | Update a document |

See [`examples/multi_agent_agreement.ts`](./examples/multi_agent_agreement.ts) for a complete multi-agent agreement demo.

## Testing

The `@hai.ai/jacs/testing` module provides zero-setup test helpers:

```typescript
import { createTestClient, createTestClientSync } from '@hai.ai/jacs/testing';

// Async (preferred)
const client = await createTestClient('ring-Ed25519');
const signed = await client.signMessage({ hello: 'test' });
const result = await client.verify(signed.raw);
assert(result.valid);

// Sync
const client2 = createTestClientSync('ring-Ed25519');
const signed2 = client2.signMessageSync({ hello: 'test' });
const result2 = client2.verifySync(signed2.raw);
assert(result2.valid);
```

## HAI Integration

The JACS package includes integration with HAI's key distribution service for fetching public keys without requiring local key storage.

### Fetch Remote Keys

```javascript
const { fetchRemoteKey } = require('@hai.ai/jacs');

// Fetch a public key from HAI's key service
const keyInfo = fetchRemoteKey('550e8400-e29b-41d4-a716-446655440000', 'latest');
console.log('Algorithm:', keyInfo.algorithm);
console.log('Public Key Hash:', keyInfo.publicKeyHash);
console.log('Agent ID:', keyInfo.agentId);
console.log('Version:', keyInfo.version);

// Use the public key for verification
const publicKeyBytes = keyInfo.publicKey; // Buffer containing DER-encoded key
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HAI_KEYS_BASE_URL` | Base URL for the HAI key service | `https://keys.hai.ai` |

### HAI Types

```typescript
interface RemotePublicKeyInfo {
  publicKey: Buffer;      // DER-encoded public key bytes
  algorithm: string;      // e.g., "ed25519", "rsa-pss-sha256"
  publicKeyHash: string;  // SHA-256 hash of the public key
  agentId: string;        // The agent's unique identifier
  version: string;        // The key version
}
```

## See Also

- [JACS Book](https://humanassisted.github.io/JACS/) - Full documentation (published book)
- [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Source](https://github.com/HumanAssisted/JACS) - GitHub repository
- [HAI Developer Portal](https://hai.ai/dev)
- [Examples](./examples/)
