# API Reference

Complete API documentation for the `@hai.ai/jacs` Node.js package.

## Installation

```bash
npm install @hai.ai/jacs
```

## v0.7.0: Async-First API

All NAPI operations now return Promises by default. Sync variants are available with a `Sync` suffix, following the Node.js convention (like `fs.readFile` vs `fs.readFileSync`).

```javascript
// Async (default, recommended)
await agent.load('./jacs.config.json');
const doc = await agent.createDocument(JSON.stringify(content));

// Sync (blocks event loop)
agent.loadSync('./jacs.config.json');
const doc = agent.createDocumentSync(JSON.stringify(content));
```

## Core Module

```javascript
import { JacsAgent, hashString, createConfig } from '@hai.ai/jacs';
```

---

## JacsAgent Class

The `JacsAgent` class is the primary interface for JACS operations. Each instance maintains its own state and can be used independently, allowing multiple agents in the same process.

### Constructor

```javascript
new JacsAgent()
```

Creates a new empty JacsAgent instance. Call `load()` or `loadSync()` to initialize with a configuration.

**Example:**
```javascript
const agent = new JacsAgent();
await agent.load('./jacs.config.json');
```

---

### agent.load(configPath) / agent.loadSync(configPath)

Load and initialize the agent from a configuration file.

**Parameters:**
- `configPath` (string): Path to the JACS configuration file

**Returns:** `Promise<string>` (async) or `string` (sync) -- The loaded agent's JSON

**Example:**
```javascript
const agent = new JacsAgent();

// Async (recommended)
const agentJson = await agent.load('./jacs.config.json');

// Sync
const agentJson = agent.loadSync('./jacs.config.json');

console.log('Agent loaded:', JSON.parse(agentJson).jacsId);
```

---

### agent.createDocument(...) / agent.createDocumentSync(...)

Create and sign a new JACS document.

**Parameters:**
- `documentString` (string): JSON string of the document content
- `customSchema` (string, optional): Path to a custom JSON Schema for validation
- `outputFilename` (string, optional): Filename to save the document
- `noSave` (boolean, optional): If true, don't save to storage (default: false)
- `attachments` (string, optional): Path to file attachments
- `embed` (boolean, optional): If true, embed attachments in the document

**Returns:** `Promise<string>` (async) or `string` (sync) -- The signed document as a JSON string

**Example:**
```javascript
// Basic document creation (async)
const doc = await agent.createDocument(JSON.stringify({
  title: 'My Document',
  content: 'Hello, World!'
}));

// Without saving (sync)
const tempDoc = agent.createDocumentSync(
  JSON.stringify({ data: 'temporary' }),
  null, null, true
);
```

---

### agent.verifyDocument(...) / agent.verifyDocumentSync(...)

Verify a document's signature and hash integrity.

**Parameters:**
- `documentString` (string): The signed document JSON string

**Returns:** `Promise<boolean>` (async) or `boolean` (sync) -- True if the document is valid

**Example:**
```javascript
const isValid = await agent.verifyDocument(signedDocumentJson);
if (isValid) {
  console.log('Document signature verified');
}
```

---

### agent.verifySignature(...) / agent.verifySignatureSync(...)

Verify a document's signature with an optional custom signature field.

**Parameters:**
- `documentString` (string): The signed document JSON string
- `signatureField` (string, optional): Name of the signature field (default: 'jacsSignature')

**Returns:** `Promise<boolean>` (async) or `boolean` (sync)

---

### agent.updateDocument(...) / agent.updateDocumentSync(...)

Update an existing document, creating a new version.

**Parameters:**
- `documentKey` (string): The document key in format `"id:version"`
- `newDocumentString` (string): The modified document as JSON string
- `attachments` (Array<string>, optional): Array of attachment file paths
- `embed` (boolean, optional): If true, embed attachments

**Returns:** `Promise<string>` (async) or `string` (sync)

**Example:**
```javascript
const doc = JSON.parse(signedDoc);
const documentKey = `${doc.jacsId}:${doc.jacsVersion}`;
const updatedDoc = await agent.updateDocument(
  documentKey,
  JSON.stringify({ ...doc, title: 'Updated Title' })
);
```

---

### agent.createAgreement(...) / agent.createAgreementSync(...)

Add an agreement requiring multiple agent signatures to a document.

**Parameters:**
- `documentString` (string): The document JSON string
- `agentIds` (Array<string>): Array of agent IDs required to sign
- `question` (string, optional): The agreement question
- `context` (string, optional): Additional context
- `agreementFieldName` (string, optional): Field name (default: 'jacsAgreement')

**Returns:** `Promise<string>` (async) or `string` (sync)

---

### agent.signAgreement(...) / agent.signAgreementSync(...)

Sign an agreement as the current agent.

**Parameters:**
- `documentString` (string): The document with agreement JSON string
- `agreementFieldName` (string, optional): Field name (default: 'jacsAgreement')

**Returns:** `Promise<string>` (async) or `string` (sync)

---

### agent.checkAgreement(...) / agent.checkAgreementSync(...)

Check the status of an agreement.

**Parameters:**
- `documentString` (string): The document with agreement JSON string
- `agreementFieldName` (string, optional): Field name (default: 'jacsAgreement')

**Returns:** `Promise<string>` (async) or `string` (sync) -- JSON string with agreement status

---

### agent.signString(...) / agent.signStringSync(...)

Sign arbitrary string data with the agent's private key.

**Parameters:**
- `data` (string): The data to sign

**Returns:** `Promise<string>` (async) or `string` (sync) -- Base64-encoded signature

---

### agent.verifyString(...) / agent.verifyStringSync(...)

Verify a signature on arbitrary string data.

**Parameters:**
- `data` (string): The original data
- `signatureBase64` (string): The base64-encoded signature
- `publicKey` (Buffer): The public key as a Buffer
- `publicKeyEncType` (string): The key algorithm (e.g., 'ring-Ed25519')

**Returns:** `Promise<boolean>` (async) or `boolean` (sync)

---

### agent.signRequest(params) -- V8-thread-only

Sign a request payload, wrapping it in a JACS document. This method is synchronous (no `Sync` suffix) because it uses V8-thread-only APIs.

**Parameters:**
- `params` (any): The request payload object

**Returns:** string -- JACS-signed request as a JSON string

---

### agent.verifyResponse(documentString) -- V8-thread-only

Verify a JACS-signed response and extract the payload. Synchronous only.

**Parameters:**
- `documentString` (string): The JACS-signed response

**Returns:** object -- Object containing the verified payload

---

### agent.verifyResponseWithAgentId(documentString) -- V8-thread-only

Verify a response and return both the payload and signer's agent ID. Synchronous only.

**Parameters:**
- `documentString` (string): The JACS-signed response

**Returns:** object -- Object with payload and agent ID

---

### agent.verifyAgent(...) / agent.verifyAgentSync(...)

Verify the agent's own signature and hash, or verify another agent file.

**Parameters:**
- `agentFile` (string, optional): Path to an agent file to verify

**Returns:** `Promise<boolean>` (async) or `boolean` (sync)

---

### agent.updateAgent(...) / agent.updateAgentSync(...)

Update the agent document with new data.

**Parameters:**
- `newAgentString` (string): The modified agent document as JSON string

**Returns:** `Promise<string>` (async) or `string` (sync)

---

### agent.signAgent(...) / agent.signAgentSync(...)

Sign another agent's document with a registration signature.

**Parameters:**
- `agentString` (string): The agent document to sign
- `publicKey` (Buffer): The public key as a Buffer
- `publicKeyEncType` (string): The key algorithm

**Returns:** `Promise<string>` (async) or `string` (sync)

---

## Utility Functions

### hashString(data)

Hash a string using SHA-256.

**Parameters:**
- `data` (string): The string to hash

**Returns:** string -- Hexadecimal hash string

```javascript
import { hashString } from '@hai.ai/jacs';
const hash = hashString('data to hash');
```

---

### createConfig(options)

Create a JACS configuration JSON string programmatically.

**Parameters:**
- `jacsUseSecurity` (string, optional)
- `jacsDataDirectory` (string, optional)
- `jacsKeyDirectory` (string, optional)
- `jacsAgentPrivateKeyFilename` (string, optional)
- `jacsAgentPublicKeyFilename` (string, optional)
- `jacsAgentKeyAlgorithm` (string, optional)
- `jacsPrivateKeyPassword` (string, optional)
- `jacsAgentIdAndVersion` (string, optional)
- `jacsDefaultStorage` (string, optional)

**Returns:** string -- Configuration as JSON string

---

## HTTP Module

```javascript
import { JACSExpressMiddleware, JACSKoaMiddleware } from '@hai.ai/jacs/http';
```

### JACSExpressMiddleware(options)

Express middleware for JACS request/response handling.

**Parameters:**
- `options.configPath` (string): Path to JACS configuration file

**Returns:** Express middleware function

---

### JACSKoaMiddleware(options)

Koa middleware for JACS request/response handling.

**Parameters:**
- `options.configPath` (string): Path to JACS configuration file

**Returns:** Koa middleware function

---

## MCP Module

```javascript
import {
  JACSTransportProxy,
  createJACSTransportProxy,
  createJACSTransportProxyAsync
} from '@hai.ai/jacs/mcp';
```

### createJACSTransportProxy(transport, configPath, role)

Factory function for creating a transport proxy.

**Parameters:**
- `transport`: The underlying MCP transport
- `configPath` (string): Path to JACS configuration file
- `role` (string): 'server' or 'client'

**Returns:** JACSTransportProxy instance

---

### createJACSTransportProxyAsync(transport, configPath, role)

Async factory that waits for JACS to be fully loaded.

**Returns:** Promise<JACSTransportProxy>

---

## TypeScript Support

The package includes full TypeScript definitions. Import types as needed:

```typescript
import { JacsAgent, hashString, createConfig } from '@hai.ai/jacs';

const agent: JacsAgent = new JacsAgent();
const hash: string = hashString('data');
```

---

## Deprecated Functions

The following module-level functions are deprecated. Use `new JacsAgent()` and instance methods instead:

- `load()` -> Use `agent.load()` / `agent.loadSync()`
- `signAgent()` -> Use `agent.signAgent()` / `agent.signAgentSync()`
- `verifyString()` -> Use `agent.verifyString()` / `agent.verifyStringSync()`
- `signString()` -> Use `agent.signString()` / `agent.signStringSync()`
- `verifyAgent()` -> Use `agent.verifyAgent()` / `agent.verifyAgentSync()`
- `updateAgent()` -> Use `agent.updateAgent()` / `agent.updateAgentSync()`
- `verifyDocument()` -> Use `agent.verifyDocument()` / `agent.verifyDocumentSync()`
- `updateDocument()` -> Use `agent.updateDocument()` / `agent.updateDocumentSync()`
- `verifySignature()` -> Use `agent.verifySignature()` / `agent.verifySignatureSync()`
- `createAgreement()` -> Use `agent.createAgreement()` / `agent.createAgreementSync()`
- `signAgreement()` -> Use `agent.signAgreement()` / `agent.signAgreementSync()`
- `createDocument()` -> Use `agent.createDocument()` / `agent.createDocumentSync()`
- `checkAgreement()` -> Use `agent.checkAgreement()` / `agent.checkAgreementSync()`
- `signRequest()` -> Use `agent.signRequest()` (V8-thread-only, sync)
- `verifyResponse()` -> Use `agent.verifyResponse()` (V8-thread-only, sync)
- `verifyResponseWithAgentId()` -> Use `agent.verifyResponseWithAgentId()` (V8-thread-only, sync)

**Migration Example:**
```javascript
// Old (deprecated, v0.6.x)
import jacs from '@hai.ai/jacs';
jacs.load('./jacs.config.json');
const doc = jacs.createDocument(JSON.stringify({ data: 'test' }));

// New (v0.7.0, async)
import { JacsAgent } from '@hai.ai/jacs';
const agent = new JacsAgent();
await agent.load('./jacs.config.json');
const doc = await agent.createDocument(JSON.stringify({ data: 'test' }));

// New (v0.7.0, sync)
import { JacsAgent } from '@hai.ai/jacs';
const agent = new JacsAgent();
agent.loadSync('./jacs.config.json');
const doc = agent.createDocumentSync(JSON.stringify({ data: 'test' }));
```

---

## Error Handling

All methods may throw errors. Use try/catch for error handling:

```javascript
try {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');
  const doc = await agent.createDocument(JSON.stringify({ data: 'test' }));
} catch (error) {
  console.error('JACS error:', error.message);
}
```

---

## See Also

- [Installation](installation.md) - Getting started
- [Basic Usage](basic-usage.md) - Common usage patterns
- [MCP Integration](mcp.md) - Model Context Protocol
- [HTTP Server](http.md) - HTTP integration
- [Express Middleware](express.md) - Express.js patterns
