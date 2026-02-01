# JACS for Node.js

Sign and verify AI agent communications with cryptographic signatures.

## Installation

```bash
npm install @hai-ai/jacs
```

## Quick Start

```javascript
const jacs = require('@hai-ai/jacs/simple');

// Load your agent (run `jacs create` first if needed)
const agent = jacs.load('./jacs.config.json');

// Sign a message
const signed = jacs.signMessage({
  action: 'approve',
  amount: 100
});

// Verify it
const result = jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}`);
console.log(`Signer: ${result.signerId}`);
```

## Core API

| Function | Description |
|----------|-------------|
| `load(configPath)` | Load agent from config file |
| `verifySelf()` | Verify agent's own integrity |
| `updateAgent(data)` | Update agent document with new data |
| `updateDocument(id, data)` | Update existing document with new data |
| `signMessage(data)` | Sign any JSON data |
| `signFile(path, embed)` | Sign a file |
| `verify(doc)` | Verify signed document |
| `getPublicKey()` | Get public key for sharing |
| `isLoaded()` | Check if agent is loaded |

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

## Examples

### Sign and Verify

```javascript
const jacs = require('@hai-ai/jacs/simple');

jacs.load('./jacs.config.json');

// Sign data
const signed = jacs.signMessage({
  action: 'transfer',
  amount: 500,
  to: 'agent-123'
});

// Later, verify received data
const result = jacs.verify(receivedJson);
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
const updated = jacs.updateAgent(agentDoc);
console.log('Agent updated with new version');
```

### Update Document

```javascript
// Create a document
const signed = jacs.signMessage({ status: 'pending', amount: 100 });

// Later, update it
const doc = JSON.parse(signed.raw);
doc.content.status = 'approved';
const updated = jacs.updateDocument(signed.documentId, doc);
console.log('Document updated with new version');
```

### File Signing

```javascript
// Reference only (stores hash)
const signed = jacs.signFile('contract.pdf', false);

// Embed content (portable document)
const embedded = jacs.signFile('contract.pdf', true);
```

### MCP Integration

```javascript
import { JacsMcpServer } from '@hai-ai/jacs/mcp';

const server = new JacsMcpServer({
  name: 'MyServer',
  version: '1.0.0',
  configPath: './jacs.config.json'
});
```

## See Also

- [JACS Documentation](https://hai.ai/jacs)
- [Examples](./examples/)
