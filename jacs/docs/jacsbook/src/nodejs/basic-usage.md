# Basic Usage

This chapter covers fundamental JACS operations in Node.js, including agent initialization, document creation, signing, and verification.

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

## Initializing an Agent

### Create and Load Agent

```javascript
import { JacsAgent } from '@hai.ai/jacs';

// Create a new agent instance
const agent = new JacsAgent();

// Load configuration from file (async)
await agent.load('./jacs.config.json');

// Or use sync variant
agent.loadSync('./jacs.config.json');
```

### Configuration File

Create `jacs.config.json`:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_default_storage": "fs",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_id_and_version": "agent-uuid:version-uuid"
}
```

## Creating Documents

### Basic Document Creation

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
await agent.load('./jacs.config.json');

// Create a document from JSON
const documentData = {
  title: "Project Proposal",
  content: "Quarterly development plan",
  budget: 50000
};

const signedDocument = await agent.createDocument(JSON.stringify(documentData));
console.log('Signed document:', signedDocument);
```

### With Custom Schema

Validate against a custom JSON Schema:

```javascript
const signedDocument = await agent.createDocument(
  JSON.stringify(documentData),
  './schemas/proposal.schema.json'  // custom schema path
);
```

### With Output File

```javascript
const signedDocument = await agent.createDocument(
  JSON.stringify(documentData),
  null,                    // no custom schema
  './output/proposal.json' // output filename
);
```

### Without Saving

```javascript
const signedDocument = await agent.createDocument(
  JSON.stringify(documentData),
  null,   // no custom schema
  null,   // no output filename
  true    // noSave = true
);
```

### With Attachments

```javascript
const signedDocument = await agent.createDocument(
  JSON.stringify(documentData),
  null,                      // no custom schema
  null,                      // no output filename
  false,                     // save the document
  './attachments/report.pdf', // attachment path
  true                       // embed files
);
```

## Verifying Documents

### Verify Document Signature

```javascript
// Verify a document's signature and hash
const isValid = await agent.verifyDocument(signedDocumentJson);
console.log('Document valid:', isValid);
```

### Verify Specific Signature Field

```javascript
// Verify with a custom signature field
const isValid = await agent.verifySignature(
  signedDocumentJson,
  'jacsSignature'  // signature field name
);
```

## Updating Documents

### Update Existing Document

```javascript
// Original document key format: "id:version"
const documentKey = 'doc-uuid:version-uuid';

// Modified document content
const updatedData = {
  jacsId: 'doc-uuid',
  jacsVersion: 'version-uuid',
  title: "Updated Proposal",
  content: "Revised quarterly plan",
  budget: 75000
};

const updatedDocument = await agent.updateDocument(
  documentKey,
  JSON.stringify(updatedData)
);

console.log('Updated document:', updatedDocument);
```

### Update with New Attachments

```javascript
const updatedDocument = await agent.updateDocument(
  documentKey,
  JSON.stringify(updatedData),
  ['./new-report.pdf'],  // new attachments
  true                   // embed files
);
```

## Signing and Verification

### Sign Arbitrary Data

```javascript
// Sign any string data
const signature = await agent.signString('Important message to sign');
console.log('Signature:', signature);
```

### Verify Arbitrary Data

```javascript
// Verify a signature on string data
const isValid = await agent.verifyString(
  'Important message to sign',  // original data
  signatureBase64,              // base64 signature
  publicKeyBuffer,              // public key as Buffer
  'ring-Ed25519'                // algorithm
);
```

## Working with Agreements

### Create an Agreement

```javascript
// Add agreement requiring multiple agent signatures
const documentWithAgreement = await agent.createAgreement(
  signedDocumentJson,
  ['agent1-uuid', 'agent2-uuid'],           // required signers
  'Do you agree to these terms?',            // question
  'Q1 2024 service contract',                // context
  'jacsAgreement'                            // field name
);
```

### Sign an Agreement

```javascript
// Sign the agreement as the current agent
const signedAgreement = await agent.signAgreement(
  documentWithAgreementJson,
  'jacsAgreement'  // agreement field name
);
```

### Check Agreement Status

```javascript
// Check which agents have signed
const status = await agent.checkAgreement(
  documentWithAgreementJson,
  'jacsAgreement'
);

console.log('Agreement status:', JSON.parse(status));
```

## Agent Operations

### Verify Agent

```javascript
// Verify the loaded agent's signature
const isValid = await agent.verifyAgent();
console.log('Agent valid:', isValid);
```

### Update Agent

```javascript
// Update agent document
const updatedAgentJson = await agent.updateAgent(JSON.stringify({
  jacsId: 'agent-uuid',
  jacsVersion: 'version-uuid',
  name: 'Updated Agent Name',
  description: 'Updated description'
}));
```

### Sign External Agent

```javascript
// Sign another agent's document with registration signature
const signedAgentJson = await agent.signAgent(
  externalAgentJson,
  publicKeyBuffer,
  'ring-Ed25519'
);
```

## Request/Response Signing

These methods remain synchronous (V8-thread-only, no `Sync` suffix):

### Sign a Request

```javascript
// Sign request parameters as a JACS document
const signedRequest = agent.signRequest({
  method: 'GET',
  path: '/api/resource',
  timestamp: new Date().toISOString(),
  body: { query: 'data' }
});
```

### Verify a Response

```javascript
// Verify a signed response
const result = agent.verifyResponse(signedResponseJson);
console.log('Response valid:', result);

// Verify and get signer's agent ID
const resultWithId = agent.verifyResponseWithAgentId(signedResponseJson);
console.log('Signer ID:', resultWithId);
```

## Utility Functions

### Hash String

```javascript
import { hashString } from '@hai.ai/jacs';

// SHA-256 hash of a string
const hash = hashString('data to hash');
console.log('Hash:', hash);
```

### Create Configuration

```javascript
import { createConfig } from '@hai.ai/jacs';

// Programmatically create a config JSON string
const configJson = createConfig(
  undefined,            // jacs_use_security
  './jacs_data',        // jacs_data_directory
  './jacs_keys',        // jacs_key_directory
  undefined,            // private key filename
  undefined,            // public key filename
  'ring-Ed25519',       // key algorithm
  undefined,            // private key password
  undefined,            // agent id and version
  'fs'                  // default storage
);

console.log('Config:', configJson);
```

## Error Handling

```javascript
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();

try {
  await agent.load('./jacs.config.json');
} catch (error) {
  console.error('Failed to load agent:', error.message);
}

try {
  const doc = await agent.createDocument(JSON.stringify({ data: 'test' }));
  console.log('Document created');
} catch (error) {
  console.error('Failed to create document:', error.message);
}

try {
  const isValid = await agent.verifyDocument(invalidJson);
} catch (error) {
  console.error('Verification failed:', error.message);
}
```

## Complete Example

```javascript
import { JacsAgent, hashString } from '@hai.ai/jacs';

async function main() {
  // Initialize agent
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  // Create a task document
  const task = {
    title: 'Code Review',
    description: 'Review pull request #123',
    assignee: 'developer-uuid',
    deadline: '2024-02-01'
  };

  const signedTask = await agent.createDocument(JSON.stringify(task));
  console.log('Task created');

  // Verify the task
  if (await agent.verifyDocument(signedTask)) {
    console.log('Task signature valid');
  }

  // Create agreement for task acceptance
  const taskWithAgreement = await agent.createAgreement(
    signedTask,
    ['manager-uuid', 'developer-uuid'],
    'Do you accept this task assignment?'
  );

  // Sign the agreement
  const signedAgreement = await agent.signAgreement(taskWithAgreement);
  console.log('Agreement signed');

  // Check agreement status
  const status = await agent.checkAgreement(signedAgreement);
  console.log('Status:', status);

  // Hash some data for reference
  const taskHash = hashString(signedTask);
  console.log('Task hash:', taskHash);
}

main().catch(console.error);
```

## Next Steps

- [MCP Integration](mcp.md) - Model Context Protocol support
- [HTTP Server](http.md) - Create HTTP APIs
- [Express Middleware](express.md) - Express.js integration
- [API Reference](api.md) - Complete API documentation
