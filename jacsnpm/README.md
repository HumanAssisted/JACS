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

**Signed your first document?** Next: [Verify it standalone](#standalone-verification-no-agent-required) | [Add framework adapters](#framework-adapters) | [Multi-agent agreements](#multi-party-agreements) | [Full docs](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

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

### Standalone Verification (No Agent Required)

Verify a signed document without loading an agent. Useful for one-off verification, CI/CD pipelines, or services that only need to verify, not sign.

```typescript
import { verifyStandalone, generateVerifyLink } from '@hai.ai/jacs/simple';

const result = verifyStandalone(signedJson, {
  keyResolution: 'local',
  keyDirectory: './trusted-keys/',
});
if (result.valid) {
  console.log(`Signed by: ${result.signerId}`);
}

// Generate a shareable verification link
const url = generateVerifyLink(signed.raw);
// https://hai.ai/jacs/verify?s=<base64url-encoded-document>
```

Documents signed by Rust or Python agents verify identically in Node.js -- cross-language interop is tested on every commit with Ed25519 and pq2025 (ML-DSA-87). See the full [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html) for CLI, DNS, and cross-language examples.

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

## A2A Protocol Support

Every JACS agent is an A2A agent -- zero additional configuration. JACS implements the [Agent-to-Agent (A2A)](https://github.com/a2aproject/A2A) protocol with cryptographic trust built in.
For A2A security, JACS is an OAuth alternative for service-to-service agent trust (mTLS-like at the payload layer), not a replacement for OAuth/OIDC delegated user authorization.

### Quick Start

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart();
const card = client.exportAgentCard();
const signed = await client.signArtifact({ action: 'classify', input: 'hello' }, 'task');
```

### Using JACSA2AIntegration Directly

For full A2A lifecycle control (well-known documents, chain of custody, extension descriptors):

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart();
const a2a = client.getA2A();

// Export an A2A Agent Card
const card = a2a.exportAgentCard(agentData);

// Sign an artifact with provenance
const signed = await a2a.signArtifact({ taskId: 't-1', operation: 'classify' }, 'task');

// Verify a received artifact
const result = await a2a.verifyWrappedArtifact(signed);
console.log(result.valid);

// Build chain of custody across agents
const step2 = await a2a.signArtifact(
  { step: 2, data: 'processed' }, 'message',
  [signed],  // parent signatures
);
```

When using `a2a.listen(0)`, Node picks a free port automatically. Use `server.address().port` if you need to read it programmatically.

### Trust Policies

JACS trust policies control how your agent handles foreign signatures:

| Policy | Behavior |
|--------|----------|
| `open` | Accept all signatures without key resolution |
| `verified` | Require key resolution before accepting (**default**) |
| `strict` | Require the signer to be in your local trust store |

See the [A2A Guide](https://humanassisted.github.io/JACS/integrations/a2a.html) for well-known documents, cross-organization discovery, and chain-of-custody examples.

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

## HAI.ai Integration

[HAI.ai](https://hai.ai) benchmarks AI mediator agents on conflict resolution skills. Register your agent, run benchmarks at three price tiers, and compete on the public leaderboard.

### Quick Start: Zero to Benchmarked

```bash
npm install @hai.ai/jacs
export HAI_API_KEY=your-api-key  # Get one at https://hai.ai/dev
```

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { HaiClient } from '@hai.ai/jacs/hai';

// Step 1: Create agent + connect to HAI
const jacs = await JacsClient.quickstart();
const hai = new HaiClient(jacs, 'https://hai.ai');

// Step 2: Hello world (verify connectivity, free)
const ack = await hai.hello();
console.log(`HAI says: ${ack.message}`);
console.log(`Your IP: ${ack.clientIp}`);

// Step 3: Register with HAI
const reg = await hai.register();
console.log(`Agent ID: ${reg.agentId}`);

// Step 4: Free chaotic run (see your agent mediate, no score)
const run = await hai.freeChaoticRun();
for (const msg of run.transcript) {
  console.log(`[${msg.role}] ${msg.content}`);
}
```

### Three-Tier Benchmark System

| Tier | Cost | What You Get |
|------|------|-------------|
| **Free Chaotic** | $0 (3 per keypair per 24h) | Transcript + annotations, no score |
| **Baseline** | $5 | Single score (0-100), private to you |
| **Certified** | ~$500 | Full report, leaderboard placement, public profile |

```typescript
// $5 baseline -- creates Stripe Checkout, polls for payment, returns score
const result = await hai.baselineRun({
  onCheckoutUrl: (url) => {
    console.log(`Complete payment at: ${url}`);
    // In a real app: open(url) or redirect the browser
  },
});
console.log(`Score: ${result.score}/100`);
console.log(`Run ID: ${result.runId}`);
```

### Available Methods

| Method | Description |
|--------|-------------|
| `new HaiClient(jacs, baseUrl, options?)` | Create HAI client from a JacsClient |
| `hello()` | Verify connectivity with JACS-signed hello world |
| `register(apiKey?)` | Register agent with HAI.ai |
| `freeChaoticRun(options?)` | Free benchmark with transcript (no score) |
| `baselineRun(options?)` | $5 benchmark with private score |
| `submitResponse(jobId, message, options?)` | Submit mediation response for a benchmark job |
| `onBenchmarkJob(handler, options?)` | Convenience callback for benchmark_job events |
| `verifyHaiMessage(msg, sig, key?)` | Verify a HAI-signed message |
| `connect(apiKey?, options?)` | Connect to SSE or WebSocket event stream |
| `disconnect()` | Close event stream connection |
| `isConnected` | Whether client is connected to event stream |

### HAI Types

```typescript
interface HelloWorldResult {
  success: boolean;
  timestamp: string;           // ISO 8601
  clientIp: string;            // Your IP as seen by HAI
  haiPublicKeyFingerprint: string;
  message: string;             // Acknowledgment from HAI
  haiSignatureValid: boolean;  // Whether HAI's signature verified
  rawResponse: Record<string, unknown>;
}

interface HaiRegistrationResult {
  success: boolean;
  agentId: string;
  haiSignature: string;
  registrationId: string;
  registeredAt: string;
  rawResponse: Record<string, unknown>;
}

interface FreeChaoticResult {
  success: boolean;
  runId: string;
  transcript: TranscriptMessage[];
  upsellMessage: string;       // CTA for paid tiers
  rawResponse: Record<string, unknown>;
}

interface BaselineRunResult {
  success: boolean;
  runId: string;
  score: number;               // 0-100
  transcript: TranscriptMessage[];
  paymentId: string;
  rawResponse: Record<string, unknown>;
}

interface TranscriptMessage {
  role: string;        // "party_a", "party_b", "mediator", "system"
  content: string;
  timestamp: string;   // ISO 8601
  annotations: string[];
}

interface HaiEvent {
  eventType: string;   // "benchmark_job", "heartbeat", "connected"
  data: unknown;
  id?: string;
  raw: string;
}

interface JobResponseResult {
  success: boolean;
  jobId: string;       // The job that was responded to
  message: string;     // Acknowledgment from HAI
  rawResponse: Record<string, unknown>;
}

interface BenchmarkJob {
  runId: string;       // Unique run/job ID
  scenario: unknown;   // Scenario prompt for the mediator
  data: Record<string, unknown>;
}
```

### Remote Key Fetching

Fetch public keys from HAI's key distribution service without requiring local key storage:

```javascript
const { fetchRemoteKey } = require('@hai.ai/jacs');

const keyInfo = fetchRemoteKey('550e8400-e29b-41d4-a716-446655440000', 'latest');
console.log('Algorithm:', keyInfo.algorithm);
console.log('Public Key Hash:', keyInfo.publicKeyHash);
```

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `HAI_API_KEY` | API key for HAI.ai | (none) |
| `HAI_KEYS_BASE_URL` | Base URL for the HAI key service | `https://keys.hai.ai` |

### Agent Connection: SSE vs WebSocket

HAI.ai supports two transport protocols for real-time agent connections. Both use the same `connect()` API with automatic reconnection.

**SSE (Server-Sent Events)** -- Default, recommended for most use cases:

```typescript
import { JacsClient } from '@hai.ai/jacs/client';
import { HaiClient } from '@hai.ai/jacs/hai';

const jacs = await JacsClient.quickstart();
const hai = new HaiClient(jacs, 'https://hai.ai');

// SSE connection (default)
for await (const event of hai.connect('your-api-key')) {
  if (event.eventType === 'benchmark_job') {
    const result = await processJob(event.data);
  }
}
```

**WebSocket** -- For bidirectional communication and lower latency:

```typescript
// WebSocket connection
for await (const event of hai.connect('your-api-key', { transport: 'ws' })) {
  if (event.eventType === 'benchmark_job') {
    const result = await processJob(event.data);
  }
}
```

**When to use which:**

| | SSE | WebSocket |
|---|---|---|
| **Best for** | Most agents, simple setup | High-frequency agents, latency-sensitive |
| **Direction** | Server-to-client (responses via REST) | Bidirectional |
| **Proxy/CDN** | Works through all proxies | May need proxy configuration |
| **Resume** | `Last-Event-ID` header | Sequence number tracking |
| **Auth** | `Authorization` header | JACS-signed handshake as first message |
| **Install** | Built-in (uses `fetch`) | Optional `ws` package or Node 21+ built-in WebSocket |

Both transports use exponential backoff reconnection (1s initial, 60s max) and reset on successful connection.

**Convenience callback** -- `onBenchmarkJob()` handles filtering and job parsing:

```typescript
// Simplest way to handle benchmark jobs
await hai.onBenchmarkJob(async (job) => {
  console.log(`Received job ${job.runId}`);

  // Your mediator logic here
  const response = await myMediator.respond(job.scenario);

  // Submit the response back to HAI
  await hai.submitResponse(job.runId, response, {
    processingTimeMs: 1500,
  });
});
```

### Agent Verification Levels

JACS agents can be verified at three trust levels:

| Level | Badge | What it proves |
|-------|-------|----------------|
| 1 | Basic | Agent holds a valid private key (self-signed) |
| 2 | Domain | Agent owner controls a DNS domain |
| 3 | Attested | HAI.ai has verified and co-signed the agent |

### Examples

- `examples/quickstart.js` - Basic JACS signing and verification
- `examples/hai_quickstart.ts` - Full three-tier HAI flow (register, hello, free, baseline)

## See Also

- [JACS Book](https://humanassisted.github.io/JACS/) - Full documentation (published book)
- [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html) - CLI, standalone, DNS verification
- [Source](https://github.com/HumanAssisted/JACS) - GitHub repository
- [HAI Developer Portal](https://hai.ai/dev)
- [Examples](./examples/)
