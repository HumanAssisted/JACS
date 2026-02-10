# Node.js Examples

This chapter provides practical Node.js examples using the `@hai.ai/jacs` package.

## Setup

```bash
# Install dependencies
npm install @hai.ai/jacs express @modelcontextprotocol/sdk zod
```

v0.7.0 uses an async-first API. All NAPI operations return Promises by default; sync variants use a `Sync` suffix.

```javascript
// Initialize JACS (ES Modules, async)
import { JacsAgent } from '@hai.ai/jacs';

const agent = new JacsAgent();
await agent.load('./jacs.config.json');
```

## Basic Document Operations

### Creating and Signing Documents

```javascript
import { JacsAgent } from '@hai.ai/jacs';

async function createSignedDocument() {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  // Create a simple document
  const content = {
    title: 'Invoice',
    invoiceNumber: 'INV-001',
    amount: 1500.00,
    customer: 'Acme Corp',
    items: [
      { description: 'Consulting', quantity: 10, price: 150 }
    ]
  };

  // Create and sign the document
  const signedDoc = await agent.createDocument(JSON.stringify(content));

  // Parse the result
  const doc = JSON.parse(signedDoc);
  console.log('Document ID:', doc.jacsId);
  console.log('Version:', doc.jacsVersion);
  console.log('Signature:', doc.jacsSignature ? 'Present' : 'Missing');

  return doc;
}

createSignedDocument();
```

### Verifying Documents

```javascript
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';

async function verifyDocument(filePath) {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  // Read the document
  const docString = fs.readFileSync(filePath, 'utf-8');

  // Verify signature
  const isValid = await agent.verifyDocument(docString);

  if (isValid) {
    console.log('✓ Document signature is valid');
    const doc = JSON.parse(docString);
    console.log('  Signed by:', doc.jacsSignature?.agentID);
    console.log('  Signed at:', doc.jacsSignature?.date);
  } else {
    console.log('✗ Document signature is INVALID');
  }

  return isValid;
}

verifyDocument('./invoice.json');
```

### Updating Documents

```javascript
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';

async function updateDocument(originalPath, newContent) {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  // Read original document
  const originalDoc = fs.readFileSync(originalPath, 'utf-8');

  // Update with new content (preserves version chain)
  const updatedDoc = await agent.updateDocument(
    originalDoc,
    JSON.stringify(newContent)
  );

  const doc = JSON.parse(updatedDoc);
  console.log('Updated Document ID:', doc.jacsId);
  console.log('New Version:', doc.jacsVersion);

  return doc;
}

// Usage
const updated = await updateDocument('./invoice-v1.json', {
  title: 'Invoice',
  invoiceNumber: 'INV-001',
  amount: 1500.00,
  customer: 'Acme Corp',
  status: 'paid'  // New field
});
```

## HTTP Server with Express

### Complete Express Server

```javascript
import express from 'express';
import { JACSExpressMiddleware } from '@hai.ai/jacs/http';
import { JacsAgent } from '@hai.ai/jacs';

const app = express();
const PORT = 3000;

// Initialize JACS
const agent = new JacsAgent();
await agent.load('./jacs.config.json');

// Health check (no JACS)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// JACS-protected API routes
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

// Validation middleware
function requirePayload(req, res, next) {
  if (!req.jacsPayload) {
    return res.status(400).json({
      error: 'Invalid JACS request',
      message: 'Request must be signed with valid JACS credentials'
    });
  }
  next();
}

// Echo endpoint
app.post('/api/echo', requirePayload, (req, res) => {
  res.send({
    echo: req.jacsPayload,
    serverTime: new Date().toISOString()
  });
});

// Calculate endpoint
app.post('/api/calculate', requirePayload, (req, res) => {
  const { operation, a, b } = req.jacsPayload;

  let result;
  switch (operation) {
    case 'add': result = a + b; break;
    case 'subtract': result = a - b; break;
    case 'multiply': result = a * b; break;
    case 'divide': result = b !== 0 ? a / b : null; break;
    default:
      return res.status(400).send({ error: 'Unknown operation' });
  }

  res.send({ operation, a, b, result });
});

// Create document endpoint
app.post('/api/documents', requirePayload, async (req, res) => {
  try {
    const signedDoc = await agent.createDocument(
      JSON.stringify(req.jacsPayload)
    );
    const doc = JSON.parse(signedDoc);

    res.send({
      success: true,
      documentId: doc.jacsId,
      version: doc.jacsVersion
    });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`JACS Express server running on port ${PORT}`);
});
```

### HTTP Client

```javascript
import { JacsAgent } from '@hai.ai/jacs';

async function callJacsApi(url, payload) {
  const agent = new JacsAgent();
  await agent.load('./jacs.client.config.json');

  // Sign the request
  const signedRequest = await agent.signRequest(payload);

  // Send HTTP request
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: signedRequest
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  // Verify and extract response
  const responseText = await response.text();
  const verified = await agent.verifyResponse(responseText);

  return verified.payload;
}

// Usage
async function main() {
  // Call echo endpoint
  const echoResult = await callJacsApi(
    'http://localhost:3000/api/echo',
    { message: 'Hello, server!' }
  );
  console.log('Echo:', echoResult);

  // Call calculate endpoint
  const calcResult = await callJacsApi(
    'http://localhost:3000/api/calculate',
    { operation: 'multiply', a: 7, b: 6 }
  );
  console.log('Calculate:', calcResult);
}

main().catch(console.error);
```

## MCP Integration

### MCP Server

```javascript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';
import { z } from 'zod';

const JACS_CONFIG = "./jacs.server.config.json";

async function main() {
  console.error("JACS MCP Server starting...");

  // Create transport with JACS encryption
  const baseTransport = new StdioServerTransport();
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    JACS_CONFIG,
    "server"
  );

  // Create MCP server
  const server = new McpServer({
    name: "jacs-demo-server",
    version: "1.0.0"
  });

  // Register tools
  server.tool("echo", {
    message: z.string().describe("Message to echo")
  }, async ({ message }) => {
    console.error(`Echo called: ${message}`);
    return { content: [{ type: "text", text: `Echo: ${message}` }] };
  });

  server.tool("calculate", {
    operation: z.enum(["add", "subtract", "multiply", "divide"]),
    a: z.number(),
    b: z.number()
  }, async ({ operation, a, b }) => {
    let result;
    switch (operation) {
      case 'add': result = a + b; break;
      case 'subtract': result = a - b; break;
      case 'multiply': result = a * b; break;
      case 'divide': result = b !== 0 ? a / b : 'undefined'; break;
    }
    return { content: [{ type: "text", text: `${a} ${operation} ${b} = ${result}` }] };
  });

  // Register resource
  server.resource(
    "server-info",
    "info://server",
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: JSON.stringify({
          name: "JACS Demo Server",
          version: "1.0.0",
          capabilities: ["echo", "calculate"]
        }),
        mimeType: "application/json"
      }]
    })
  );

  // Connect
  await server.connect(secureTransport);
  console.error("Server running with JACS encryption");
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
```

### MCP Client

```javascript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createJACSTransportProxy } from '@hai.ai/jacs/mcp';

const JACS_CONFIG = "./jacs.client.config.json";

async function main() {
  console.log("JACS MCP Client starting...");

  // Connect to server
  const baseTransport = new StdioClientTransport({
    command: 'node',
    args: ['mcp-server.js']
  });

  const secureTransport = createJACSTransportProxy(
    baseTransport,
    JACS_CONFIG,
    "client"
  );

  const client = new Client({
    name: "jacs-demo-client",
    version: "1.0.0"
  }, {
    capabilities: { tools: {} }
  });

  await client.connect(secureTransport);
  console.log("Connected to JACS MCP Server");

  // List tools
  const tools = await client.listTools();
  console.log("Available tools:", tools.tools.map(t => t.name));

  // Call echo
  const echoResult = await client.callTool({
    name: "echo",
    arguments: { message: "Hello, JACS!" }
  });
  console.log("Echo:", echoResult.content[0].text);

  // Call calculate
  const calcResult = await client.callTool({
    name: "calculate",
    arguments: { operation: "multiply", a: 6, b: 7 }
  });
  console.log("Calculate:", calcResult.content[0].text);

  await client.close();
  console.log("Done!");
}

main().catch(console.error);
```

## Agreements

### Creating Multi-Party Agreements

```javascript
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';

async function createAgreement() {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  // Create the contract document
  const contract = {
    type: 'service_agreement',
    title: 'Professional Services Agreement',
    parties: ['Company A', 'Company B'],
    terms: 'Terms and conditions here...',
    value: 50000,
    effectiveDate: '2024-02-01'
  };

  const signedContract = await agent.createDocument(JSON.stringify(contract));

  // Get agent IDs (replace with actual UUIDs)
  const agentIds = [
    'agent1-uuid-here',
    'agent2-uuid-here'
  ];

  // Create agreement
  const agreementDoc = await agent.createAgreement(
    signedContract,
    agentIds,
    'Do you agree to the terms of this service agreement?',
    'This is a legally binding agreement'
  );

  console.log('Agreement created');
  const doc = JSON.parse(agreementDoc);
  console.log('Document ID:', doc.jacsId);
  console.log('Required signatures:', doc.jacsAgreement?.agentIDs?.length);

  // Save for signing
  fs.writeFileSync('agreement-pending.json', agreementDoc);

  return doc;
}

createAgreement();
```

### Signing Agreements

```javascript
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';

async function signAgreement(agreementPath, outputPath) {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  // Read agreement
  const agreementDoc = fs.readFileSync(agreementPath, 'utf-8');

  // Sign agreement
  const signedAgreement = await agent.signAgreement(agreementDoc);

  // Check status
  const statusJson = await agent.checkAgreement(signedAgreement);
  const status = JSON.parse(statusJson);

  console.log('Agreement signed');
  console.log('Status:', status.complete ? 'Complete' : 'Pending');
  console.log('Signatures:', status.signatures?.length || 0);

  // Save
  fs.writeFileSync(outputPath, signedAgreement);

  return status;
}

signAgreement('./agreement-pending.json', './agreement-signed.json');
```

### Checking Agreement Status

```javascript
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';

async function checkAgreementStatus(agreementPath) {
  const agent = new JacsAgent();
  await agent.load('./jacs.config.json');

  const agreementDoc = fs.readFileSync(agreementPath, 'utf-8');
  const statusJson = await agent.checkAgreement(agreementDoc);
  const status = JSON.parse(statusJson);

  console.log('Agreement Status:');
  console.log('  Complete:', status.complete);
  console.log('  Required agents:', status.requiredAgents);
  console.log('  Signed by:', status.signedBy || []);
  console.log('  Missing:', status.missing || []);

  return status;
}

checkAgreementStatus('./agreement.json');
```

## Document Store

### Simple File-Based Store

```javascript
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';
import path from 'path';

class JacsDocumentStore {
  constructor(configPath, dataDir = './documents') {
    this.configPath = configPath;
    this.dataDir = dataDir;
    this.agent = null;
  }

  async initialize() {
    this.agent = new JacsAgent();
    await this.agent.load(this.configPath);

    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
  }

  async create(content) {
    const signedDoc = await this.agent.createDocument(JSON.stringify(content));
    const doc = JSON.parse(signedDoc);

    const filename = `${doc.jacsId}.json`;
    const filepath = path.join(this.dataDir, filename);

    fs.writeFileSync(filepath, signedDoc);

    return { id: doc.jacsId, version: doc.jacsVersion, path: filepath };
  }

  async get(documentId) {
    const filepath = path.join(this.dataDir, `${documentId}.json`);

    if (!fs.existsSync(filepath)) {
      return null;
    }

    const docString = fs.readFileSync(filepath, 'utf-8');
    return JSON.parse(docString);
  }

  async verify(documentId) {
    const filepath = path.join(this.dataDir, `${documentId}.json`);

    if (!fs.existsSync(filepath)) {
      return { valid: false, error: 'Document not found' };
    }

    const docString = fs.readFileSync(filepath, 'utf-8');
    const isValid = await this.agent.verifyDocument(docString);

    return { valid: isValid, document: JSON.parse(docString) };
  }

  list() {
    const files = fs.readdirSync(this.dataDir);
    return files
      .filter(f => f.endsWith('.json'))
      .map(f => f.replace('.json', ''));
  }
}

// Usage
async function main() {
  const store = new JacsDocumentStore('./jacs.config.json');
  await store.initialize();

  // Create document
  const result = await store.create({
    type: 'note',
    title: 'Meeting Notes',
    content: 'Discussed project timeline...'
  });
  console.log('Created:', result.id);

  // Verify document
  const verification = await store.verify(result.id);
  console.log('Valid:', verification.valid);

  // List all documents
  const docs = store.list();
  console.log('Documents:', docs);
}

main();
```

## Error Handling

### Robust Error Handling Pattern

```javascript
import { JacsAgent } from '@hai.ai/jacs';

class JacsError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'JacsError';
    this.code = code;
    this.details = details;
  }
}

async function robustDocumentCreate(configPath, content) {
  let agent;

  try {
    agent = new JacsAgent();
    await agent.load(configPath);
  } catch (error) {
    throw new JacsError(
      'Failed to initialize JACS agent',
      'INIT_ERROR',
      { originalError: error.message }
    );
  }

  try {
    const signedDoc = await agent.createDocument(JSON.stringify(content));
    return JSON.parse(signedDoc);
  } catch (error) {
    throw new JacsError(
      'Failed to create document',
      'CREATE_ERROR',
      { originalError: error.message, content }
    );
  }
}

async function robustDocumentVerify(configPath, docString) {
  let agent;

  try {
    agent = new JacsAgent();
    await agent.load(configPath);
  } catch (error) {
    throw new JacsError(
      'Failed to initialize JACS agent',
      'INIT_ERROR',
      { originalError: error.message }
    );
  }

  try {
    const isValid = await agent.verifyDocument(docString);
    return { valid: isValid };
  } catch (error) {
    throw new JacsError(
      'Verification error',
      'VERIFY_ERROR',
      { originalError: error.message }
    );
  }
}

// Usage with error handling
async function main() {
  try {
    const doc = await robustDocumentCreate('./jacs.config.json', {
      title: 'Test'
    });
    console.log('Created:', doc.jacsId);
  } catch (error) {
    if (error instanceof JacsError) {
      console.error(`JACS Error [${error.code}]:`, error.message);
      console.error('Details:', error.details);
    } else {
      console.error('Unexpected error:', error);
    }
  }
}

main();
```

## Testing

### Jest Test Setup

```javascript
// tests/jacs.test.js
import { JacsAgent } from '@hai.ai/jacs';
import fs from 'fs';
import path from 'path';
import os from 'os';

describe('JACS Document Operations', () => {
  let agent;
  let tempDir;
  let configPath;

  beforeAll(async () => {
    // Create temp directory
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-test-'));
    const dataDir = path.join(tempDir, 'data');
    const keyDir = path.join(tempDir, 'keys');

    fs.mkdirSync(dataDir);
    fs.mkdirSync(keyDir);

    // Create test config
    const config = {
      jacs_data_directory: dataDir,
      jacs_key_directory: keyDir,
      jacs_agent_key_algorithm: 'ring-Ed25519',
      jacs_default_storage: 'fs'
    };

    configPath = path.join(tempDir, 'jacs.config.json');
    fs.writeFileSync(configPath, JSON.stringify(config));

    // Initialize agent
    agent = new JacsAgent();
    await agent.load(configPath);
  });

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true });
  });

  test('creates a signed document', async () => {
    const content = { title: 'Test Document', value: 42 };
    const signedDoc = await agent.createDocument(JSON.stringify(content));
    const doc = JSON.parse(signedDoc);

    expect(doc.jacsId).toBeDefined();
    expect(doc.jacsVersion).toBeDefined();
    expect(doc.jacsSignature).toBeDefined();
    expect(doc.title).toBe('Test Document');
  });

  test('verifies a valid document', async () => {
    const content = { title: 'Verify Test' };
    const signedDoc = await agent.createDocument(JSON.stringify(content));

    const isValid = await agent.verifyDocument(signedDoc);
    expect(isValid).toBe(true);
  });

  test('detects tampered document', async () => {
    const content = { title: 'Tamper Test' };
    const signedDoc = await agent.createDocument(JSON.stringify(content));

    // Tamper with document
    const doc = JSON.parse(signedDoc);
    doc.title = 'Modified Title';
    const tamperedDoc = JSON.stringify(doc);

    const isValid = await agent.verifyDocument(tamperedDoc);
    expect(isValid).toBe(false);
  });
});
```

## See Also

- [Node.js Installation](../nodejs/installation.md) - Setup guide
- [Node.js API Reference](../nodejs/api.md) - Complete API documentation
- [MCP Integration](../nodejs/mcp.md) - MCP details
- [HTTP Server](../nodejs/http.md) - HTTP integration
