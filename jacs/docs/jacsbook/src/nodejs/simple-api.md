# Simplified API

The simplified API (`@hai.ai/jacs/simple`) provides a streamlined, module-level interface for common JACS operations. It's designed to get you signing and verifying in under 2 minutes.

## v0.7.0: Async-First API

{{#include ../_snippets/node-async-first.md}}

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

{{#include ../_snippets/quickstart-persistent-agent.md}}
Pass `{ algorithm: 'ring-Ed25519' }` to override the default (`pq2025`).

To load an existing agent explicitly, use `load()` instead:

```javascript
const agent = await jacs.load('./jacs.config.json');
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
```

## When to Use the Simplified API

| Simplified API | JacsAgent Class |
|----------------|-----------------|
| Quick prototyping | Multiple agents in one process |
| Scripts and CLI tools | Complex multi-document workflows |
| MCP tool implementations | Fine-grained control |
| Single-agent applications | Custom error handling |

---

## API Reference

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

---

### quickstart(options?)

Create a persistent agent with keys on disk. If `./jacs.config.json` already exists, loads it. Otherwise creates a new agent, saving keys and config to disk. If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure password is auto-generated and saved to `./jacs_keys/.jacs_password`. Call this once before `signMessage()` or `verify()`.

**Parameters:**
- `options` (object, optional): `{ algorithm?: string }`. Default algorithm: `"pq2025"`. Also: `"ring-Ed25519"`, `"RSA-PSS"`.

**Returns:** `Promise<AgentInfo>` (async) or `AgentInfo` (sync)

```javascript
const info = await jacs.quickstart();
console.log(`Agent ID: ${info.agentId}`);

// Or with a specific algorithm
const info = await jacs.quickstart({ algorithm: 'ring-Ed25519' });

// Sync variant (blocks event loop)
const info = jacs.quickstartSync({ algorithm: 'ring-Ed25519' });
```

---

### load(configPath?)

Load a persistent agent from a configuration file. Use this instead of `quickstart()` when you want to load a specific config file explicitly.

**Parameters:**
- `configPath` (string, optional): Path to jacs.config.json (default: "./jacs.config.json")

**Returns:** `Promise<AgentInfo>` (async) or `AgentInfo` (sync)

```javascript
const info = await jacs.load('./jacs.config.json');
console.log(`Agent ID: ${info.agentId}`);

// Sync variant
const info = jacs.loadSync('./jacs.config.json');
```

---

### isLoaded()

Check if an agent is currently loaded.

**Returns:** boolean

```javascript
if (!jacs.isLoaded()) {
  await jacs.load('./jacs.config.json');
}
```

---

### getAgentInfo()

Get information about the currently loaded agent.

**Returns:** `AgentInfo` or null if no agent is loaded

```javascript
const info = jacs.getAgentInfo();
if (info) {
  console.log(`Agent: ${info.agentId}`);
}
```

---

### verifySelf()

Verify the loaded agent's own integrity (signature and hash).

**Returns:** `Promise<VerificationResult>` (async) or `VerificationResult` (sync)

**Throws:** Error if no agent is loaded

```javascript
const result = await jacs.verifySelf();
if (result.valid) {
  console.log('Agent integrity verified');
} else {
  console.log('Errors:', result.errors);
}
```

---

### signMessage(data)

Sign arbitrary data as a JACS document.

**Parameters:**
- `data` (any): Object, array, string, or any JSON-serializable value

**Returns:** `Promise<SignedDocument>` (async) or `SignedDocument` (sync)

**Throws:** Error if no agent is loaded

```javascript
// Async (recommended)
const signed = await jacs.signMessage({
  action: 'transfer',
  amount: 500,
  recipient: 'agent-123'
});

// Sync
const signed = jacs.signMessageSync({
  action: 'transfer',
  amount: 500,
  recipient: 'agent-123'
});

console.log(`Document ID: ${signed.documentId}`);
console.log(`Signed by: ${signed.agentId}`);
```

---

### signFile(filePath, embed?)

Sign a file with optional content embedding.

**Parameters:**
- `filePath` (string): Path to the file to sign
- `embed` (boolean, optional): If true, embed file content in the document (default: false)

**Returns:** `Promise<SignedDocument>` (async) or `SignedDocument` (sync)

```javascript
// Reference only (stores hash)
const signed = await jacs.signFile('contract.pdf', false);

// Embed content (creates portable document)
const embedded = await jacs.signFile('contract.pdf', true);
```

---

### verify(signedDocument)

Verify a signed document and extract its content.

**Parameters:**
- `signedDocument` (string): The JSON string of the signed document

**Returns:** `Promise<VerificationResult>` (async) or `VerificationResult` (sync)

```javascript
const result = await jacs.verify(signedJson);

if (result.valid) {
  console.log(`Signed by: ${result.signerId}`);
  console.log(`Data: ${JSON.stringify(result.data)}`);
} else {
  console.log(`Invalid: ${result.errors.join(', ')}`);
}
```

---

### verifyStandalone(signedDocument, options?)

Verify a signed document **without** loading an agent. Use when you only need to verify (e.g. a lightweight API). Does not use the global agent.

**Parameters:**
- `signedDocument` (string): The signed JACS document JSON
- `options` (object, optional): `{ keyResolution?, dataDirectory?, keyDirectory? }`

**Returns:** `VerificationResult` (always sync -- no NAPI call)

```javascript
const result = jacs.verifyStandalone(signedJson, { keyResolution: 'local', keyDirectory: './keys' });
console.log(result.valid, result.signerId);
```

---

### audit(options?)

Run a read-only security audit and health checks. Returns an object with `risks`, `health_checks`, `summary`, and `overall_status`. Does not require a loaded agent; does not modify state.

**Parameters:** `options` (object, optional): `{ configPath?, recentN? }`

**Returns:** `Promise<object>` (async) or `object` (sync)

See [Security Model -- Security Audit](../advanced/security.md#security-audit-audit) for full details and options.

```javascript
const result = await jacs.audit();
console.log(`Risks: ${result.risks.length}, Status: ${result.overall_status}`);
```

---

### updateAgent(newAgentData)

Update the agent document with new data and re-sign it.

This function expects a **complete agent document** (not partial updates). Use `exportAgent()` to get the current document, modify it, then pass it here.

**Parameters:**
- `newAgentData` (object|string): Complete agent document as JSON string or object

**Returns:** `Promise<string>` (async) or `string` (sync) -- The updated and re-signed agent document

```javascript
const agentDoc = JSON.parse(jacs.exportAgent());
agentDoc.jacsAgentType = 'hybrid';
const updated = await jacs.updateAgent(agentDoc);
```

---

### updateDocument(documentId, newDocumentData, attachments?, embed?)

Update an existing document with new data and re-sign it.

**Parameters:**
- `documentId` (string): The document ID (jacsId) to update
- `newDocumentData` (object|string): Updated document as JSON string or object
- `attachments` (string[], optional): Array of file paths to attach
- `embed` (boolean, optional): If true, embed attachment contents

**Returns:** `Promise<SignedDocument>` (async) or `SignedDocument` (sync)

```javascript
const original = await jacs.signMessage({ status: 'pending', amount: 100 });
const doc = JSON.parse(original.raw);
doc.content.status = 'approved';
const updated = await jacs.updateDocument(original.documentId, doc);
```

---

### exportAgent()

Export the current agent document for sharing or inspection.

**Returns:** string -- The agent JSON document (pure sync, no suffix needed)

```javascript
const agentDoc = jacs.exportAgent();
const agent = JSON.parse(agentDoc);
console.log(`Agent type: ${agent.jacsAgentType}`);
```

---

### getDnsRecord(domain, ttl?)

Return the DNS TXT record line for the loaded agent. Pure sync, no suffix needed.

**Parameters:** `domain` (string), `ttl` (number, optional, default 3600)

**Returns:** string

---

### getWellKnownJson()

Return the well-known JSON object for the loaded agent. Pure sync, no suffix needed.

**Returns:** object

---

### getPublicKey()

Get the loaded agent's public key in PEM format. Pure sync, no suffix needed.

**Returns:** string -- PEM-encoded public key

```javascript
const pem = jacs.getPublicKey();
console.log(pem);
```

---

## Type Definitions

### AgentInfo

```typescript
interface AgentInfo {
  agentId: string;      // Agent's UUID
  name: string;         // Agent name from config
  publicKeyPath: string; // Path to public key file
  configPath: string;   // Path to loaded config
}
```

### SignedDocument

```typescript
interface SignedDocument {
  raw: string;          // Full JSON document with signature
  documentId: string;   // Document's UUID (jacsId)
  agentId: string;      // Signing agent's ID
  timestamp: string;    // ISO 8601 timestamp
}
```

### VerificationResult

```typescript
interface VerificationResult {
  valid: boolean;       // True if signature verified
  data?: any;           // Extracted document content
  signerId: string;     // Agent who signed
  timestamp: string;    // When it was signed
  attachments: Attachment[];  // File attachments
  errors: string[];     // Error messages if invalid
}
```

### Attachment

```typescript
interface Attachment {
  filename: string;     // Original filename
  mimeType: string;     // MIME type
  hash: string;         // SHA-256 hash
  embedded: boolean;    // True if content is embedded
  content?: Buffer;     // Embedded content (if available)
}
```

---

## Complete Example

```javascript
const jacs = require('@hai.ai/jacs/simple');

// Load agent
const agent = await jacs.load('./jacs.config.json');
console.log(`Loaded agent: ${agent.agentId}`);

// Verify agent integrity
const selfCheck = await jacs.verifySelf();
if (!selfCheck.valid) {
  throw new Error('Agent integrity check failed');
}

// Sign a transaction
const transaction = {
  type: 'payment',
  from: agent.agentId,
  to: 'recipient-agent-uuid',
  amount: 250.00,
  currency: 'USD',
  memo: 'Q1 Service Payment'
};

const signed = await jacs.signMessage(transaction);
console.log(`Transaction signed: ${signed.documentId}`);

// Verify the transaction (simulating recipient)
const verification = await jacs.verify(signed.raw);

if (verification.valid) {
  console.log(`Payment verified from: ${verification.signerId}`);
  console.log(`Amount: ${verification.data.amount} ${verification.data.currency}`);
} else {
  console.log(`Verification failed: ${verification.errors.join(', ')}`);
}

// Sign a file
const contractSigned = await jacs.signFile('./contract.pdf', true);
console.log(`Contract signed: ${contractSigned.documentId}`);

// Update agent metadata
const agentDoc = JSON.parse(jacs.exportAgent());
agentDoc.jacsAgentType = 'ai';
const updatedAgent = await jacs.updateAgent(agentDoc);
console.log('Agent metadata updated');

// Share public key
const publicKey = jacs.getPublicKey();
console.log('Share this public key for verification:');
console.log(publicKey);
```

---

## MCP Integration

The simplified API works well with MCP tool implementations:

```javascript
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const jacs = require('@hai.ai/jacs/simple');

// Load agent once at startup
await jacs.load('./jacs.config.json');

// Define a signed tool
server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;

  if (name === 'approve_request') {
    const signed = await jacs.signMessage({
      action: 'approve',
      requestId: args.requestId,
      approvedBy: jacs.getAgentInfo().agentId
    });

    return {
      content: [{ type: 'text', text: signed.raw }]
    };
  }
});
```

---

## Error Handling

```javascript
const jacs = require('@hai.ai/jacs/simple');

try {
  await jacs.load('./missing-config.json');
} catch (e) {
  console.error('Config not found:', e.message);
}

try {
  // Will fail if no agent loaded
  await jacs.signMessage({ data: 'test' });
} catch (e) {
  console.error('No agent:', e.message);
}

try {
  await jacs.signFile('/nonexistent/file.pdf');
} catch (e) {
  console.error('File not found:', e.message);
}

// Verification doesn't throw - check result.valid
const result = await jacs.verify('invalid json');
if (!result.valid) {
  console.error('Verification errors:', result.errors);
}
```

---

## See Also

- [Basic Usage](basic-usage.md) - JacsAgent class usage
- [API Reference](api.md) - Complete JacsAgent API
- [MCP Integration](mcp.md) - Model Context Protocol
