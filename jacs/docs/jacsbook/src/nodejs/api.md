# API Reference

Complete API documentation for the `@hai.ai/jacs` Node.js package.

## Installation

```bash
npm install @hai.ai/jacs
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

Creates a new empty JacsAgent instance. Call `load()` to initialize with a configuration.

**Example:**
```javascript
const agent = new JacsAgent();
agent.load('./jacs.config.json');
```

---

### agent.load(configPath)

Load and initialize the agent from a configuration file.

**Parameters:**
- `configPath` (string): Path to the JACS configuration file

**Returns:** string - The loaded agent's JSON

**Example:**
```javascript
const agent = new JacsAgent();
const agentJson = agent.load('./jacs.config.json');
console.log('Agent loaded:', JSON.parse(agentJson).jacsId);
```

---

### agent.createDocument(documentString, customSchema?, outputFilename?, noSave?, attachments?, embed?)

Create and sign a new JACS document.

**Parameters:**
- `documentString` (string): JSON string of the document content
- `customSchema` (string, optional): Path to a custom JSON Schema for validation
- `outputFilename` (string, optional): Filename to save the document
- `noSave` (boolean, optional): If true, don't save to storage (default: false)
- `attachments` (string, optional): Path to file attachments
- `embed` (boolean, optional): If true, embed attachments in the document

**Returns:** string - The signed document as a JSON string

**Example:**
```javascript
// Basic document creation
const doc = agent.createDocument(JSON.stringify({
  title: 'My Document',
  content: 'Hello, World!'
}));

// With custom schema
const validatedDoc = agent.createDocument(
  JSON.stringify({ title: 'Validated', amount: 100 }),
  './schemas/invoice.schema.json'
);

// Without saving
const tempDoc = agent.createDocument(
  JSON.stringify({ data: 'temporary' }),
  null,
  null,
  true  // noSave = true
);

// With attachments
const docWithFile = agent.createDocument(
  JSON.stringify({ report: 'Monthly Report' }),
  null,
  null,
  false,
  './report.pdf',
  true  // embed = true
);
```

---

### agent.verifyDocument(documentString)

Verify a document's signature and hash integrity.

**Parameters:**
- `documentString` (string): The signed document JSON string

**Returns:** boolean - True if the document is valid

**Example:**
```javascript
const isValid = agent.verifyDocument(signedDocumentJson);
if (isValid) {
  console.log('Document signature verified');
} else {
  console.log('Document verification failed');
}
```

---

### agent.verifySignature(documentString, signatureField?)

Verify a document's signature with an optional custom signature field.

**Parameters:**
- `documentString` (string): The signed document JSON string
- `signatureField` (string, optional): Name of the signature field (default: 'jacsSignature')

**Returns:** boolean - True if the signature is valid

**Example:**
```javascript
// Verify default signature field
const isValid = agent.verifySignature(docJson);

// Verify custom signature field
const isValidCustom = agent.verifySignature(docJson, 'customSignature');
```

---

### agent.updateDocument(documentKey, newDocumentString, attachments?, embed?)

Update an existing document, creating a new version.

**Parameters:**
- `documentKey` (string): The document key in format `"id:version"`
- `newDocumentString` (string): The modified document as JSON string
- `attachments` (Array<string>, optional): Array of attachment file paths
- `embed` (boolean, optional): If true, embed attachments

**Returns:** string - The updated document as a JSON string

**Example:**
```javascript
// Parse existing document to get key
const doc = JSON.parse(signedDoc);
const documentKey = `${doc.jacsId}:${doc.jacsVersion}`;

// Update the document
const updatedDoc = agent.updateDocument(
  documentKey,
  JSON.stringify({
    ...doc,
    title: 'Updated Title',
    content: 'Modified content'
  })
);
```

---

### agent.createAgreement(documentString, agentIds, question?, context?, agreementFieldName?)

Add an agreement requiring multiple agent signatures to a document.

**Parameters:**
- `documentString` (string): The document JSON string
- `agentIds` (Array<string>): Array of agent IDs required to sign
- `question` (string, optional): The agreement question
- `context` (string, optional): Additional context for the agreement
- `agreementFieldName` (string, optional): Field name for the agreement (default: 'jacsAgreement')

**Returns:** string - The document with agreement as a JSON string

**Example:**
```javascript
const docWithAgreement = agent.createAgreement(
  signedDocumentJson,
  ['agent-1-uuid', 'agent-2-uuid', 'agent-3-uuid'],
  'Do you agree to these terms?',
  'Q1 2024 Service Agreement',
  'jacsAgreement'
);
```

---

### agent.signAgreement(documentString, agreementFieldName?)

Sign an agreement as the current agent.

**Parameters:**
- `documentString` (string): The document with agreement JSON string
- `agreementFieldName` (string, optional): Field name of the agreement (default: 'jacsAgreement')

**Returns:** string - The document with this agent's signature added

**Example:**
```javascript
const signedAgreement = agent.signAgreement(
  docWithAgreementJson,
  'jacsAgreement'
);
```

---

### agent.checkAgreement(documentString, agreementFieldName?)

Check the status of an agreement (which agents have signed).

**Parameters:**
- `documentString` (string): The document with agreement JSON string
- `agreementFieldName` (string, optional): Field name of the agreement (default: 'jacsAgreement')

**Returns:** string - JSON string with agreement status

**Example:**
```javascript
const statusJson = agent.checkAgreement(signedAgreementJson);
const status = JSON.parse(statusJson);

console.log('Required signers:', status.required);
console.log('Signatures received:', status.signed);
console.log('Complete:', status.complete);
```

---

### agent.signString(data)

Sign arbitrary string data with the agent's private key.

**Parameters:**
- `data` (string): The data to sign

**Returns:** string - Base64-encoded signature

**Example:**
```javascript
const signature = agent.signString('Important message');
console.log('Signature:', signature);
```

---

### agent.verifyString(data, signatureBase64, publicKey, publicKeyEncType)

Verify a signature on arbitrary string data.

**Parameters:**
- `data` (string): The original data
- `signatureBase64` (string): The base64-encoded signature
- `publicKey` (Buffer): The public key as a Buffer
- `publicKeyEncType` (string): The key algorithm (e.g., 'ring-Ed25519')

**Returns:** boolean - True if the signature is valid

**Example:**
```javascript
const isValid = agent.verifyString(
  'Important message',
  signatureBase64,
  publicKeyBuffer,
  'ring-Ed25519'
);
```

---

### agent.signRequest(params)

Sign a request payload, wrapping it in a JACS document.

**Parameters:**
- `params` (any): The request payload object

**Returns:** string - JACS-signed request as a JSON string

**Example:**
```javascript
const signedRequest = agent.signRequest({
  method: 'GET',
  path: '/api/data',
  timestamp: new Date().toISOString(),
  body: { query: 'value' }
});
```

---

### agent.verifyResponse(documentString)

Verify a JACS-signed response and extract the payload.

**Parameters:**
- `documentString` (string): The JACS-signed response

**Returns:** object - Object containing the verified payload

**Example:**
```javascript
const result = agent.verifyResponse(jacsResponseString);
const payload = result.payload;
console.log('Verified payload:', payload);
```

---

### agent.verifyResponseWithAgentId(documentString)

Verify a response and return both the payload and signer's agent ID.

**Parameters:**
- `documentString` (string): The JACS-signed response

**Returns:** object - Object with payload and agent ID

**Example:**
```javascript
const result = agent.verifyResponseWithAgentId(jacsResponseString);
console.log('Payload:', result.payload);
console.log('Signed by agent:', result.agentId);
```

---

### agent.verifyAgent(agentFile?)

Verify the agent's own signature and hash, or verify another agent file.

**Parameters:**
- `agentFile` (string, optional): Path to an agent file to verify

**Returns:** boolean - True if the agent is valid

**Example:**
```javascript
// Verify the loaded agent
const isValid = agent.verifyAgent();

// Verify another agent file
const isOtherValid = agent.verifyAgent('./other-agent.json');
```

---

### agent.updateAgent(newAgentString)

Update the agent document with new data.

**Parameters:**
- `newAgentString` (string): The modified agent document as JSON string

**Returns:** string - The updated agent document

**Example:**
```javascript
const currentAgent = JSON.parse(agent.load('./jacs.config.json'));
const updatedAgent = agent.updateAgent(JSON.stringify({
  ...currentAgent,
  description: 'Updated description'
}));
```

---

### agent.signAgent(agentString, publicKey, publicKeyEncType)

Sign another agent's document with a registration signature.

**Parameters:**
- `agentString` (string): The agent document to sign
- `publicKey` (Buffer): The public key as a Buffer
- `publicKeyEncType` (string): The key algorithm

**Returns:** string - The signed agent document

**Example:**
```javascript
const signedAgent = agent.signAgent(
  externalAgentJson,
  publicKeyBuffer,
  'ring-Ed25519'
);
```

---

## Utility Functions

### hashString(data)

Hash a string using SHA-256.

**Parameters:**
- `data` (string): The string to hash

**Returns:** string - Hexadecimal hash string

**Example:**
```javascript
import { hashString } from '@hai.ai/jacs';

const hash = hashString('data to hash');
console.log('SHA-256:', hash);
```

---

### createConfig(options)

Create a JACS configuration JSON string programmatically.

**Parameters:**
- `jacsUseSecurity` (string, optional): Enable security features
- `jacsDataDirectory` (string, optional): Directory for data storage
- `jacsKeyDirectory` (string, optional): Directory for key storage
- `jacsAgentPrivateKeyFilename` (string, optional): Private key filename
- `jacsAgentPublicKeyFilename` (string, optional): Public key filename
- `jacsAgentKeyAlgorithm` (string, optional): Signing algorithm
- `jacsPrivateKeyPassword` (string, optional): Password for private key
- `jacsAgentIdAndVersion` (string, optional): Agent ID and version to load
- `jacsDefaultStorage` (string, optional): Storage backend ('fs', 's3', 'memory')

**Returns:** string - Configuration as JSON string

**Example:**
```javascript
import { createConfig } from '@hai.ai/jacs';

const configJson = createConfig(
  undefined,           // jacsUseSecurity
  './jacs_data',       // jacsDataDirectory
  './jacs_keys',       // jacsKeyDirectory
  undefined,           // private key filename
  undefined,           // public key filename
  'ring-Ed25519',      // algorithm
  undefined,           // password
  undefined,           // agent id
  'fs'                 // storage
);

// Write to file
fs.writeFileSync('jacs.config.json', configJson);
```

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

**Example:**
```javascript
import { JACSExpressMiddleware } from '@hai.ai/jacs/http';

app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

app.post('/api/data', (req, res) => {
  // req.jacsPayload contains verified payload
  res.send({ received: req.jacsPayload });
});
```

---

### JACSKoaMiddleware(options)

Koa middleware for JACS request/response handling.

**Parameters:**
- `options.configPath` (string): Path to JACS configuration file

**Returns:** Koa middleware function

**Example:**
```javascript
import { JACSKoaMiddleware } from '@hai.ai/jacs/http';

app.use(JACSKoaMiddleware({
  configPath: './jacs.config.json'
}));

app.use(async (ctx) => {
  // ctx.state.jacsPayload contains verified payload
  ctx.body = { received: ctx.state.jacsPayload };
});
```

---

## MCP Module

```javascript
import {
  JACSTransportProxy,
  createJACSTransportProxy,
  createJACSTransportProxyAsync
} from '@hai.ai/jacs/mcp';
```

### JACSTransportProxy

Class that wraps MCP transports with JACS encryption.

**Constructor:**
```javascript
new JACSTransportProxy(transport, role, jacsConfigPath)
```

**Parameters:**
- `transport`: Any MCP transport (Stdio, SSE, WebSocket)
- `role` (string): 'server' or 'client'
- `jacsConfigPath` (string): Path to JACS configuration file

---

### createJACSTransportProxy(transport, configPath, role)

Factory function for creating a transport proxy.

**Parameters:**
- `transport`: The underlying MCP transport
- `configPath` (string): Path to JACS configuration file
- `role` (string): 'server' or 'client'

**Returns:** JACSTransportProxy instance

**Example:**
```javascript
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const baseTransport = new StdioServerTransport();
const secureTransport = createJACSTransportProxy(
  baseTransport,
  './jacs.config.json',
  'server'
);
```

---

### createJACSTransportProxyAsync(transport, configPath, role)

Async factory that waits for JACS to be fully loaded.

**Parameters:** Same as `createJACSTransportProxy`

**Returns:** Promise<JACSTransportProxy>

**Example:**
```javascript
const secureTransport = await createJACSTransportProxyAsync(
  baseTransport,
  './jacs.config.json',
  'server'
);
```

---

## TypeScript Support

The package includes full TypeScript definitions. Import types as needed:

```typescript
import { JacsAgent, hashString, createConfig } from '@hai.ai/jacs';

const agent: JacsAgent = new JacsAgent();
const hash: string = hashString('data');
const config: string = createConfig(
  undefined,
  './data',
  './keys'
);
```

---

## Deprecated Functions

The following module-level functions are deprecated. Use `new JacsAgent()` and instance methods instead:

- `load()` - Use `agent.load()`
- `signAgent()` - Use `agent.signAgent()`
- `verifyString()` - Use `agent.verifyString()`
- `signString()` - Use `agent.signString()`
- `verifyAgent()` - Use `agent.verifyAgent()`
- `updateAgent()` - Use `agent.updateAgent()`
- `verifyDocument()` - Use `agent.verifyDocument()`
- `updateDocument()` - Use `agent.updateDocument()`
- `verifySignature()` - Use `agent.verifySignature()`
- `createAgreement()` - Use `agent.createAgreement()`
- `signAgreement()` - Use `agent.signAgreement()`
- `createDocument()` - Use `agent.createDocument()`
- `checkAgreement()` - Use `agent.checkAgreement()`
- `signRequest()` - Use `agent.signRequest()`
- `verifyResponse()` - Use `agent.verifyResponse()`
- `verifyResponseWithAgentId()` - Use `agent.verifyResponseWithAgentId()`

**Migration Example:**
```javascript
// Old (deprecated)
import jacs from '@hai.ai/jacs';
await jacs.load('./jacs.config.json');
const doc = jacs.createDocument(JSON.stringify({ data: 'test' }));

// New (recommended)
import { JacsAgent } from '@hai.ai/jacs';
const agent = new JacsAgent();
agent.load('./jacs.config.json');
const doc = agent.createDocument(JSON.stringify({ data: 'test' }));
```

---

## Error Handling

All methods may throw errors. Use try/catch for error handling:

```javascript
try {
  const agent = new JacsAgent();
  agent.load('./jacs.config.json');
  const doc = agent.createDocument(JSON.stringify({ data: 'test' }));
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
