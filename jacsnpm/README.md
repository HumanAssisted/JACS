# JACS for Node.js

Node.js bindings for JACS (JSON Agent Communication Standard) -- an open data provenance toolkit for signing and verifying AI agent communications. JACS works standalone with no server required; optionally register with [HAI.ai](https://hai.ai) for cross-organization key discovery.

**Dependencies**: The `overrides` in `package.json` for `body-parser` and `qs` are for security (CVE-2024-45590). Do not remove them without re-auditing.

## Installation

```bash
npm install @hai.ai/jacs
```

The npm package ships prebuilt native bindings for supported targets and does not compile Rust during `npm install`.

## Quick Start

Zero-config -- one call to start signing:

```javascript
const jacs = require('@hai.ai/jacs/simple');

jacs.quickstart();
const signed = jacs.signMessage({ action: 'approve', amount: 100 });
const result = jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

`quickstart()` creates a persistent agent with keys on disk. If `./jacs.config.json` already exists, it loads it; otherwise it creates a new agent. Agent, keys, and config are saved to `./jacs_data`, `./jacs_keys`, and `./jacs.config.json`. If `JACS_PRIVATE_KEY_PASSWORD` is not set, a secure password is auto-generated and saved to `./jacs_keys/.jacs_password`. Pass `{ algorithm: 'ring-Ed25519' }` to override the default (`pq2025`).

### Advanced: Loading an existing agent

If you already have an agent (e.g., created by a previous `quickstart()` call), load it explicitly:

```javascript
const jacs = require('@hai.ai/jacs/simple');

const agent = jacs.load('./jacs.config.json');

const signed = jacs.signMessage({ action: 'approve', amount: 100 });
const result = jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

## Core API

| Function | Description |
|----------|-------------|
| `quickstart(options?)` | Create a persistent agent with keys on disk -- zero config, no manual setup |
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
| `generateVerifyLink(doc, baseUrl?)` | Generate a shareable hai.ai verification URL for a signed document |

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

const agent = jacs.create({
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
const jacs = require('@hai.ai/jacs/simple');

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
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

// Wrap any MCP transport with JACS signing
const baseTransport = new StdioServerTransport();
const jacsTransport = createJACSTransportProxy(
  baseTransport, './jacs.config.json', 'server'
);
```

See `examples/mcp.simple.server.js` for a complete MCP server example with JACS-signed tools.

## JacsClient (Instance-Based API)

`JacsClient` is the recommended API for new code. Each instance owns its own agent, so multiple clients can coexist in the same process without shared global state.

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

// Zero-config: loads or creates a persistent agent
const client = JacsClient.quickstart({ algorithm: 'ring-Ed25519' });

const signed = client.signMessage({ action: 'approve', amount: 100 });
const result = client.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Ephemeral Clients

For testing or throwaway use, create an in-memory client with no files or env vars:

```typescript
const client = JacsClient.ephemeral('ring-Ed25519');
const signed = client.signMessage({ hello: 'world' });
const result = client.verify(signed.raw);
```

### Multi-Party Agreements

Create agreements that require signatures from multiple agents, with optional constraints:

```typescript
const agreement = client.createAgreement(
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
const signed = agentB.signAgreement(agreement.raw);

// Check agreement status
const status = client.checkAgreement(signed.raw);
console.log(`Complete: ${status.complete}, Signatures: ${status.signedCount}/${status.totalRequired}`);
```

### JacsClient API

| Method | Description |
|--------|-------------|
| `JacsClient.quickstart(options?)` | Load or create a persistent agent (static factory) |
| `JacsClient.ephemeral(algorithm?)` | Create an in-memory agent for testing (static factory) |
| `client.load(configPath?)` | Load agent from config file |
| `client.create(options)` | Create a new agent with keys |
| `client.signMessage(data)` | Sign any JSON data |
| `client.verify(doc)` | Verify a signed document |
| `client.verifySelf()` | Verify agent's own integrity |
| `client.verifyById(id)` | Verify by storage ID (`uuid:version`) |
| `client.signFile(path, embed?)` | Sign a file |
| `client.createAgreement(doc, agentIds, options?)` | Create a multi-party agreement |
| `client.signAgreement(doc, fieldName?)` | Sign an existing agreement |
| `client.checkAgreement(doc, fieldName?)` | Check agreement status |
| `client.updateAgent(data)` | Update and re-sign the agent document |
| `client.updateDocument(id, data)` | Update and re-sign a document |
| `client.reset()` | Clear internal state |

See [`examples/multi_agent_agreement.ts`](./examples/multi_agent_agreement.ts) for a complete multi-agent agreement demo.

## Testing

The `@hai.ai/jacs/testing` module provides a zero-setup test helper:

```typescript
import { createTestClient } from '@hai.ai/jacs/testing';

const client = createTestClient('ring-Ed25519');
const signed = client.signMessage({ hello: 'test' });
const result = client.verify(signed.raw);
assert(result.valid);
```

`createTestClient` returns a `JacsClient.ephemeral()` instance -- no config files, no key files, no env vars needed.

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
