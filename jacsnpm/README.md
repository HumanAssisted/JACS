# JACS for Node.js

Node.js bindings for JACS (JSON Agent Communication Standard) -- an open data provenance toolkit for signing and verifying AI agent communications. JACS works standalone with no server required; optionally register with [HAI.ai](https://hai.ai) for cross-organization key discovery.

**Dependencies**: The `overrides` in `package.json` for `body-parser` and `qs` are for security (CVE-2024-45590). Do not remove them without re-auditing.

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
| `create(options)` | Create a new agent programmatically (non-interactive) |
| `load(configPath)` | Load agent from config file |
| `verifySelf()` | Verify agent's own integrity |
| `updateAgent(data)` | Update agent document with new data |
| `updateDocument(id, data)` | Update existing document with new data |
| `signMessage(data)` | Sign any JSON data |
| `signFile(path, embed)` | Sign a file |
| `verify(doc)` | Verify signed document (JSON string) |
| `verifyStandalone(doc, opts?)` | Verify without loading an agent (one-off) |
| `verifyById(id)` | Verify a document by storage ID (`uuid:version`) |
| `registerWithHai(opts?)` | Register the loaded agent with HAI.ai |
| `getDnsRecord(domain, ttl?)` | Get DNS TXT record line for the agent |
| `getWellKnownJson()` | Get well-known JSON for `/.well-known/jacs-pubkey.json` |
| `reencryptKey(oldPw, newPw)` | Re-encrypt private key with new password |
| `getPublicKey()` | Get public key for sharing |
| `isLoaded()` | Check if agent is loaded |
| `trustAgent(json)` | Add an agent to the local trust store |
| `listTrustedAgents()` | List all trusted agent IDs |
| `untrustAgent(id)` | Remove an agent from the trust store |
| `isTrusted(id)` | Check if an agent is trusted |
| `getTrustedAgent(id)` | Get a trusted agent's JSON document |
| `audit(options?)` | Run a read-only security audit; optional `configPath`, `recentN` |

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
const jacs = require('@hai-ai/jacs/simple');

const agent = jacs.create({
  name: 'my-agent',
  password: process.env.JACS_PASSWORD,  // required
  algorithm: 'pq2025',                  // default; also: "ring-Ed25519", "RSA-PSS"
  dataDirectory: './jacs_data',
  keyDirectory: './jacs_keys',
});
console.log(`Created: ${agent.agentId}`);
```

### Verify by Document ID

```javascript
const result = jacs.verifyById('550e8400-e29b-41d4-a716-446655440000:1');
console.log(`Valid: ${result.valid}`);
```

### Re-encrypt Private Key

```javascript
jacs.reencryptKey('old-password-123!', 'new-Str0ng-P@ss!');
```

### Password Requirements

Passwords must be at least 8 characters and include uppercase, lowercase, a digit, and a special character.

### Algorithm Deprecation Notice

The `pq-dilithium` algorithm is deprecated. Use `pq2025` (ML-DSA-87, FIPS-204) instead. `pq-dilithium` still works but emits deprecation warnings.

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

JACS provides a transport proxy that wraps any MCP transport with automatic signing and verification at the network boundary:

```javascript
import { createJACSTransportProxy } from '@hai-ai/jacs/mcp';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

// Wrap any MCP transport with JACS signing
const baseTransport = new StdioServerTransport();
const jacsTransport = createJACSTransportProxy(
  baseTransport, './jacs.config.json', 'server'
);
```

See `examples/mcp.simple.server.js` for a complete MCP server example with JACS-signed tools.

## HAI Integration

The JACS package includes integration with HAI's key distribution service for fetching public keys without requiring local key storage.

### Fetch Remote Keys

```javascript
const { fetchRemoteKey } = require('@hai-ai/jacs');

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

- [JACS Documentation](https://hai.ai/jacs)
- [HAI Developer Portal](https://hai.ai/dev)
- [Examples](./examples/)
