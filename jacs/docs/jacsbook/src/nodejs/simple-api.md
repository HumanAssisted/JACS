# Simplified API

The simplified API (`@hai.ai/jacs/simple`) provides a streamlined, module-level interface for common JACS operations. It's designed to get you signing and verifying in under 2 minutes.

## Quick Start

```javascript
const jacs = require('@hai.ai/jacs/simple');

// Load your agent
const agent = jacs.load('./jacs.config.json');

// Sign a message
const signed = jacs.signMessage({ action: 'approve', amount: 100 });
console.log(`Document ID: ${signed.documentId}`);

// Verify it
const result = jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}`);
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

### load(configPath?)

Load an agent from a configuration file. This must be called before any other operations.

**Parameters:**
- `configPath` (string, optional): Path to jacs.config.json (default: "./jacs.config.json")

**Returns:** `AgentInfo` object

```javascript
const info = jacs.load('./jacs.config.json');
console.log(`Agent ID: ${info.agentId}`);
console.log(`Config: ${info.configPath}`);
```

---

### isLoaded()

Check if an agent is currently loaded.

**Returns:** boolean

```javascript
if (!jacs.isLoaded()) {
  jacs.load('./jacs.config.json');
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

**Returns:** `VerificationResult`

**Throws:** Error if no agent is loaded

```javascript
const result = jacs.verifySelf();
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

**Returns:** `SignedDocument`

**Throws:** Error if no agent is loaded

```javascript
// Sign an object
const signed = jacs.signMessage({
  action: 'transfer',
  amount: 500,
  recipient: 'agent-123'
});

console.log(`Document ID: ${signed.documentId}`);
console.log(`Signed by: ${signed.agentId}`);
console.log(`Timestamp: ${signed.timestamp}`);
console.log(`Raw JSON: ${signed.raw}`);
```

---

### signFile(filePath, embed?)

Sign a file with optional content embedding.

**Parameters:**
- `filePath` (string): Path to the file to sign
- `embed` (boolean, optional): If true, embed file content in the document (default: false)

**Returns:** `SignedDocument`

**Throws:** Error if file not found or no agent loaded

```javascript
// Reference only (stores hash)
const signed = jacs.signFile('contract.pdf', false);

// Embed content (creates portable document)
const embedded = jacs.signFile('contract.pdf', true);
```

---

### verify(signedDocument)

Verify a signed document and extract its content.

**Parameters:**
- `signedDocument` (string): The JSON string of the signed document

**Returns:** `VerificationResult`

**Throws:** Error if no agent is loaded

```javascript
const result = jacs.verify(signedJson);

if (result.valid) {
  console.log(`Signed by: ${result.signerId}`);
  console.log(`Timestamp: ${result.timestamp}`);
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

**Returns:** `VerificationResult` (same shape as `verify()`)

```javascript
const result = jacs.verifyStandalone(signedJson, { keyResolution: 'local', keyDirectory: './keys' });
console.log(result.valid, result.signerId);
```

---

### audit(options?)

Run a read-only security audit and health checks. Returns an object with `risks`, `health_checks`, `summary`, and `overall_status`. Does not require a loaded agent; does not modify state.

**Parameters:** `options` (object, optional): `{ configPath?, recentN? }`

**Returns:** Object with `risks`, `health_checks`, `summary`, `overall_status`, etc.

See [Security Model — Security Audit](../advanced/security.md#security-audit-audit) for full details and options.

```javascript
const result = jacs.audit();
console.log(`Risks: ${result.risks.length}, Status: ${result.overall_status}`);
```

---

### updateAgent(newAgentData)

Update the agent document with new data and re-sign it.

This function expects a **complete agent document** (not partial updates). Use `exportAgent()` to get the current document, modify it, then pass it here.

**Parameters:**
- `newAgentData` (object|string): Complete agent document as JSON string or object

**Returns:** string - The updated and re-signed agent document

**Throws:** Error if no agent loaded or validation fails

```javascript
// Get current agent document
const agentDoc = JSON.parse(jacs.exportAgent());

// Modify fields
agentDoc.jacsAgentType = 'hybrid';
agentDoc.jacsContacts = [{ contactFirstName: 'Jane', contactLastName: 'Doe' }];

// Update (creates new version, re-signs, re-hashes)
const updated = jacs.updateAgent(agentDoc);
const newDoc = JSON.parse(updated);

console.log(`New version: ${newDoc.jacsVersion}`);
console.log(`Previous: ${newDoc.jacsPreviousVersion}`);
```

**Valid `jacsAgentType` values:** `"human"`, `"human-org"`, `"hybrid"`, `"ai"`

---

### updateDocument(documentId, newDocumentData, attachments?, embed?)

Update an existing document with new data and re-sign it.

**Note:** The original document must have been saved to disk (created without `noSave: true`).

**Parameters:**
- `documentId` (string): The document ID (jacsId) to update
- `newDocumentData` (object|string): Updated document as JSON string or object
- `attachments` (string[], optional): Array of file paths to attach
- `embed` (boolean, optional): If true, embed attachment contents

**Returns:** `SignedDocument` with the updated document

**Throws:** Error if document not found, no agent loaded, or validation fails

```javascript
// Create a document (must be saved to disk)
const original = jacs.signMessage({ status: 'pending', amount: 100 });

// Later, update it
const doc = JSON.parse(original.raw);
doc.content.status = 'approved';

const updated = jacs.updateDocument(original.documentId, doc);
const newDoc = JSON.parse(updated.raw);

console.log(`New version: ${newDoc.jacsVersion}`);
console.log(`Previous: ${newDoc.jacsPreviousVersion}`);
```

---

### exportAgent()

Export the current agent document for sharing or inspection.

**Returns:** string - The agent JSON document

**Throws:** Error if no agent loaded

```javascript
const agentDoc = jacs.exportAgent();
console.log(agentDoc);

// Parse to inspect
const agent = JSON.parse(agentDoc);
console.log(`Agent type: ${agent.jacsAgentType}`);
```

---

### registerWithHai(options?)

Register the loaded agent with HAI.ai. Requires a loaded agent and an API key (`options.apiKey` or `HAI_API_KEY`).

**Parameters:** `options` (object, optional): `{ apiKey?, haiUrl?, preview? }`

**Returns:** `Promise<HaiRegistrationResult>` with `agentId`, `jacsId`, `dnsVerified`, `signatures`

---

### getDnsRecord(domain, ttl?)

Return the DNS TXT record line for the loaded agent (for DNS-based discovery). Format: `_v1.agent.jacs.{domain}. TTL IN TXT "v=hai.ai; ..."`.

**Parameters:** `domain` (string), `ttl` (number, optional, default 3600)

**Returns:** string

---

### getWellKnownJson()

Return the well-known JSON object for the loaded agent (e.g. for `/.well-known/jacs-pubkey.json`). Keys: `publicKey`, `publicKeyHash`, `algorithm`, `agentId`.

**Returns:** object

---

### getPublicKey()

Get the loaded agent's public key in PEM format for sharing with others.

**Returns:** string - PEM-encoded public key

**Throws:** Error if no agent loaded

```javascript
const pem = jacs.getPublicKey();
console.log(pem);
// -----BEGIN PUBLIC KEY-----
// ...
// -----END PUBLIC KEY-----
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
const agent = jacs.load('./jacs.config.json');
console.log(`Loaded agent: ${agent.agentId}`);

// Verify agent integrity
const selfCheck = jacs.verifySelf();
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

const signed = jacs.signMessage(transaction);
console.log(`Transaction signed: ${signed.documentId}`);

// Verify the transaction (simulating recipient)
const verification = jacs.verify(signed.raw);

if (verification.valid) {
  console.log(`Payment verified from: ${verification.signerId}`);
  console.log(`Amount: ${verification.data.amount} ${verification.data.currency}`);
} else {
  console.log(`Verification failed: ${verification.errors.join(', ')}`);
}

// Sign a file
const contractSigned = jacs.signFile('./contract.pdf', true);
console.log(`Contract signed: ${contractSigned.documentId}`);

// Update agent metadata
const agentDoc = JSON.parse(jacs.exportAgent());
agentDoc.jacsAgentType = 'ai';
if (!agentDoc.jacsContacts || agentDoc.jacsContacts.length === 0) {
  agentDoc.jacsContacts = [{ contactFirstName: 'AI', contactLastName: 'Agent' }];
}
const updatedAgent = jacs.updateAgent(agentDoc);
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
jacs.load('./jacs.config.json');

// Define a signed tool
server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;

  if (name === 'approve_request') {
    const signed = jacs.signMessage({
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
  jacs.load('./missing-config.json');
} catch (e) {
  console.error('Config not found:', e.message);
}

try {
  // Will fail if no agent loaded
  jacs.signMessage({ data: 'test' });
} catch (e) {
  console.error('No agent:', e.message);
}

try {
  jacs.signFile('/nonexistent/file.pdf');
} catch (e) {
  console.error('File not found:', e.message);
}

// Verification doesn't throw - check result.valid
const result = jacs.verify('invalid json');
if (!result.valid) {
  console.error('Verification errors:', result.errors);
}
```

---

## See Also

- [Basic Usage](basic-usage.md) - JacsAgent class usage
- [API Reference](api.md) - Complete JacsAgent API
- [MCP Integration](mcp.md) - Model Context Protocol
