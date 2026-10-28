# API Reference

{{#include ../_snippets/node-registry-status.md}}

Native API reference for the `@hai.ai/jacs` Node.js package.

## Installation

```bash
npm install @hai.ai/jacs
```

## Async and synchronous methods

{{#include ../_snippets/node-async-first.md}}

```javascript
// Async (default, recommended)
await agent.load('./jacs.config.json');
const doc = await agent.createDocument(JSON.stringify(content));

// Sync (blocks event loop)
agent.loadSync('./jacs.config.json');
const syncDoc = agent.createDocumentSync(JSON.stringify(content));
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
const syncAgentJson = agent.loadSync('./jacs.config.json');

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

**Returns:** `Promise<boolean>` (async) or `boolean` (sync) — true on success.
Invalid documents can reject/throw; handle errors rather than relying on false.

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

Legacy sidecar API for mathematical signature inspection. The report keeps
`complete`, `policy_authenticated`, and `policy_accepted` false: participant and
role policy are not authenticated. Agreement v2 is also inspection-only; see
[its guide](../guides/agreement-v2.md) before interpreting reports.

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

### agent.signArtifact(...) / agent.signArtifactSync(...)

Sign an A2A artifact with JACS provenance. This is the canonical method name.

**Parameters:**
- `artifactJson` (string): JSON string of the artifact to sign
- `artifactType` (string): Type of artifact (e.g., `"artifact"`, `"result"`)
- `parentSignaturesJson` (string, optional): JSON string of parent signatures for chain of custody

**Returns:** `Promise<string>` (async) or `string` (sync) -- The signed, wrapped artifact as a JSON string

**Example:**
```javascript
const signed = await agent.signArtifact(
  JSON.stringify({ action: 'classify', input: 'hello' }),
  'artifact'
);
```

---

### agent.wrapA2aArtifact(...) / agent.wrapA2aArtifactSync(...)

> **Deprecated since 0.9.0.** Use `signArtifact()` / `signArtifactSync()` instead. This method will be removed in 1.0.0.
>
> Set `JACS_SHOW_DEPRECATIONS=1` to see runtime warnings when deprecated methods are called.

Wraps an A2A artifact with JACS provenance signature. Identical behavior to `signArtifact()` / `signArtifactSync()`.

**Parameters:** Same as `signArtifact()` / `signArtifactSync()`.

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

### createConfig(...fields)

Create a JACS configuration JSON string using the positional arguments below.
This does not generate keys or create an agent. Never persist a private-key
password in the generated configuration.

**Parameters:**
- `jacsUseSecurity` (string, optional)
- `jacsDataDirectory` (string, optional)
- `jacsKeyDirectory` (string, optional)
- `jacsAgentPrivateKeyFilename` (string, optional)
- `jacsAgentPublicKeyFilename` (string, optional)
- `jacsAgentKeyAlgorithm` (string, optional)
- `jacsPrivateKeyPassword` (legacy slot; leave undefined)
- `jacsAgentIdAndVersion` (string, optional)
- `jacsDefaultStorage` (string, optional)

**Returns:** string -- Configuration as JSON string

---

## HTTP integration

Use `jacsMiddleware` from `@hai.ai/jacs/express` or `jacsKoaMiddleware` from
`@hai.ai/jacs/koa` for signed document bodies. The old `/http` adapter calls
removed root helpers. Request-bound authorization and pinned event verification
use `JacsSimpleAgent` instance methods; see [HTTP](http.md).

## MCP module

```typescript
createJACSTransportProxy(transport, loadedClientOrAgent, role, peerPolicy)
createJACSTransportProxyAsync(transport, configPath, role, peerPolicy)
```

The first returns `JACSTransportProxy`; the second returns a Promise after
loading the agent. `role` is `'client'` or `'server'`. Configure
`peerPolicy.expectedPeerAgentId` or `peerPolicy.allowedPeerAgentIds` on both
ends and provision trusted verification keys. The transport is local-only.
See [MCP integration](mcp.md) for actual SDK handlers, tool registration and
failure behavior.

---

## TypeScript Support

The package includes full TypeScript definitions. Import types as needed:

```typescript
import { JacsAgent, hashString, createConfig } from '@hai.ai/jacs';

const agent: JacsAgent = new JacsAgent();
const hash: string = hashString('data');
```

---

## Root exports and legacy functions

Root exports include `JacsAgent`, `JacsSimpleAgent`, `hashString`, and the
positional `createConfig` helper. Historical module-level entry points now
have explicit names such as `legacyLoad` and `legacyCreateDocument`. The old
`jacs.load()` and `jacs.createDocument()` globals are not exported.

Use instance methods or the separate `@hai.ai/jacs/simple` module:

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
await agent.load('./jacs.config.json');
const doc = await agent.createDocument(JSON.stringify({ data: 'test' }));
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
