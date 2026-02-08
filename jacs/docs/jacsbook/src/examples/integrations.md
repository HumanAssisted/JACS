# Integration Examples

This chapter provides complete, production-ready integration examples combining multiple JACS features.

## Multi-Agent Contract Signing System

A complete example of a contract signing workflow with multiple agents.

### Overview

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Seller     │     │   Contract   │     │   Buyer      │
│   Agent      │────>│   Document   │<────│   Agent      │
└──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                           ↓
                   ┌──────────────┐
                   │   Signed     │
                   │   Agreement  │
                   └──────────────┘
```

### Implementation

```javascript
// contract-system.js
import { JacsAgent } from '@hai-ai/jacs';
import fs from 'fs';

class ContractSigningSystem {
  constructor() {
    this.agents = new Map();
  }

  async registerAgent(name, configPath) {
    const agent = new JacsAgent();
    await agent.load(configPath);
    this.agents.set(name, { agent, configPath });
    return agent;
  }

  async createContract(content, sellerName) {
    const seller = this.agents.get(sellerName);
    if (!seller) throw new Error(`Agent ${sellerName} not found`);

    // Create and sign the contract
    const signedContract = await seller.agent.createDocument(
      JSON.stringify(content)
    );

    return JSON.parse(signedContract);
  }

  async createAgreement(contract, agentNames, question) {
    const firstAgent = this.agents.get(agentNames[0]);
    if (!firstAgent) throw new Error(`Agent ${agentNames[0]} not found`);

    // Get agent IDs
    const agentIds = [];
    for (const name of agentNames) {
      const agent = this.agents.get(name);
      if (!agent) throw new Error(`Agent ${name} not found`);
      // Get agent ID from config
      const config = JSON.parse(fs.readFileSync(agent.configPath, 'utf-8'));
      agentIds.push(config.jacs_agent_id_and_version.split(':')[0]);
    }

    const agreementDoc = await firstAgent.agent.createAgreement(
      JSON.stringify(contract),
      agentIds,
      question,
      'Legal contract requiring signatures from all parties'
    );

    return JSON.parse(agreementDoc);
  }

  async signAgreement(agreement, agentName) {
    const agent = this.agents.get(agentName);
    if (!agent) throw new Error(`Agent ${agentName} not found`);

    const signedDoc = await agent.agent.signAgreement(
      JSON.stringify(agreement)
    );

    return JSON.parse(signedDoc);
  }

  async checkAgreementStatus(agreement, agentName) {
    const agent = this.agents.get(agentName);
    if (!agent) throw new Error(`Agent ${agentName} not found`);

    const statusJson = await agent.agent.checkAgreement(
      JSON.stringify(agreement)
    );

    return JSON.parse(statusJson);
  }
}

// Usage
async function runContractWorkflow() {
  const system = new ContractSigningSystem();

  // Register agents
  await system.registerAgent('seller', './seller.config.json');
  await system.registerAgent('buyer', './buyer.config.json');

  // Create contract
  const contract = await system.createContract({
    type: 'purchase_agreement',
    parties: {
      seller: 'Widget Corp',
      buyer: 'Acme Inc'
    },
    items: [
      { name: 'Premium Widgets', quantity: 1000, unitPrice: 10.00 }
    ],
    totalValue: 10000,
    terms: 'Payment due within 30 days of delivery',
    effectiveDate: new Date().toISOString()
  }, 'seller');

  console.log('Contract created:', contract.jacsId);

  // Create agreement
  const agreement = await system.createAgreement(
    contract,
    ['seller', 'buyer'],
    'Do you agree to the terms of this purchase agreement?'
  );

  console.log('Agreement created, awaiting signatures');

  // Seller signs
  let signedAgreement = await system.signAgreement(agreement, 'seller');
  console.log('Seller signed');

  // Check status
  let status = await system.checkAgreementStatus(signedAgreement, 'seller');
  console.log('Status after seller:', status.complete ? 'Complete' : 'Pending');

  // Buyer signs
  signedAgreement = await system.signAgreement(signedAgreement, 'buyer');
  console.log('Buyer signed');

  // Final status
  status = await system.checkAgreementStatus(signedAgreement, 'buyer');
  console.log('Final status:', status.complete ? 'Complete' : 'Pending');

  // Save completed agreement
  fs.writeFileSync(
    './completed-agreement.json',
    JSON.stringify(signedAgreement, null, 2)
  );

  return signedAgreement;
}

runContractWorkflow().catch(console.error);
```

## Secure API Gateway with MCP Tools

A complete API gateway that authenticates requests and provides MCP tools.

### Node.js Implementation

```javascript
// api-gateway.js
import express from 'express';
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';
import { createJACSTransportProxy } from '@hai-ai/jacs/mcp';
import { JacsAgent } from '@hai-ai/jacs';
import { z } from 'zod';

// Initialize Express
const app = express();
const PORT = 3000;

// Initialize JACS
const agent = new JacsAgent();
await agent.load('./jacs.config.json');

// Create MCP server with tools
const mcpServer = new McpServer({
  name: "secure-api-gateway",
  version: "1.0.0"
});

// Document operations tool
mcpServer.tool("create_document", {
  content: z.object({}).passthrough().describe("Document content"),
  type: z.string().optional().describe("Document type")
}, async ({ content, type }) => {
  const doc = await agent.createDocument(JSON.stringify({
    ...content,
    documentType: type || 'generic'
  }));
  const parsed = JSON.parse(doc);
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        success: true,
        documentId: parsed.jacsId,
        version: parsed.jacsVersion
      })
    }]
  };
});

mcpServer.tool("verify_document", {
  document: z.string().describe("JSON document string to verify")
}, async ({ document }) => {
  try {
    const isValid = await agent.verifyDocument(document);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ valid: isValid })
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ valid: false, error: error.message })
      }]
    };
  }
});

// Health check (unauthenticated)
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// REST API routes (JACS authenticated)
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

// Document REST endpoint
app.post('/api/documents', async (req, res) => {
  if (!req.jacsPayload) {
    return res.status(400).send({ error: 'Invalid JACS request' });
  }

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

app.post('/api/documents/verify', async (req, res) => {
  if (!req.jacsPayload) {
    return res.status(400).send({ error: 'Invalid JACS request' });
  }

  try {
    const isValid = await agent.verifyDocument(
      JSON.stringify(req.jacsPayload.document)
    );
    res.send({ valid: isValid });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// MCP SSE endpoint (JACS authenticated)
const activeSessions = new Map();

app.get('/mcp/sse', async (req, res) => {
  const sessionId = Date.now().toString();

  // Create SSE transport with JACS
  const baseTransport = new SSEServerTransport('/mcp/messages', res);
  const secureTransport = createJACSTransportProxy(
    baseTransport,
    './jacs.config.json',
    'server'
  );

  activeSessions.set(sessionId, { transport: secureTransport, res });

  // Connect MCP server
  await mcpServer.connect(secureTransport);

  res.on('close', () => {
    activeSessions.delete(sessionId);
  });
});

app.post('/mcp/messages', express.text({ type: '*/*' }), async (req, res) => {
  // Find the active session and handle the message
  for (const [id, session] of activeSessions) {
    try {
      await session.transport.handlePostMessage(req, res, req.body);
      return;
    } catch (error) {
      // Try next session
    }
  }
  res.status(404).send({ error: 'No active session' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Secure API Gateway running on port ${PORT}`);
  console.log(`  REST API: http://localhost:${PORT}/api`);
  console.log(`  MCP SSE:  http://localhost:${PORT}/mcp/sse`);
});
```

### Python Implementation

```python
# api_gateway.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse
import jacs
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
import uvicorn
import json

app = FastAPI(title="Secure API Gateway")

# Initialize JACS
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create MCP server with JACS
mcp = JACSMCPServer(FastMCP("secure-api-gateway"))

@mcp.tool()
def create_document(content: dict, document_type: str = "generic") -> str:
    """Create a signed JACS document"""
    doc_content = {**content, "documentType": document_type}
    signed_doc = agent.create_document(json.dumps(doc_content))
    parsed = json.loads(signed_doc)
    return json.dumps({
        "success": True,
        "documentId": parsed["jacsId"],
        "version": parsed["jacsVersion"]
    })

@mcp.tool()
def verify_document(document: str) -> str:
    """Verify a JACS document signature"""
    try:
        is_valid = agent.verify_document(document)
        return json.dumps({"valid": is_valid})
    except Exception as e:
        return json.dumps({"valid": False, "error": str(e)})

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy"}

# REST API endpoints
@app.post("/api/documents")
async def create_doc(request: Request):
    body = await request.body()
    body_str = body.decode('utf-8')

    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid JACS request")

    signed_doc = agent.create_document(json.dumps(payload))
    doc = json.loads(signed_doc)

    result = {
        "success": True,
        "documentId": doc["jacsId"],
        "version": doc["jacsVersion"]
    }

    signed_response = jacs.sign_response(result)
    return PlainTextResponse(content=signed_response)

@app.post("/api/documents/verify")
async def verify_doc(request: Request):
    body = await request.body()
    body_str = body.decode('utf-8')

    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid JACS request")

    document = payload.get("document")
    is_valid = agent.verify_document(json.dumps(document))

    result = {"valid": is_valid}
    signed_response = jacs.sign_response(result)
    return PlainTextResponse(content=signed_response)

# Mount MCP SSE endpoint
app.mount("/mcp", mcp.sse_app())

if __name__ == "__main__":
    print("Secure API Gateway running")
    print("  REST API: http://localhost:8000/api")
    print("  MCP SSE:  http://localhost:8000/mcp/sse")
    uvicorn.run(app, host="localhost", port=8000)
```

## Document Audit Trail System

Track and verify document history with cryptographic proofs.

```javascript
// audit-trail.js
import { JacsAgent } from '@hai-ai/jacs';
import fs from 'fs';
import path from 'path';

class AuditTrailSystem {
  constructor(configPath, auditDir = './audit') {
    this.configPath = configPath;
    this.auditDir = auditDir;
    this.agent = null;
  }

  async initialize() {
    this.agent = new JacsAgent();
    await this.agent.load(this.configPath);

    if (!fs.existsSync(this.auditDir)) {
      fs.mkdirSync(this.auditDir, { recursive: true });
    }
  }

  async createDocument(content, metadata = {}) {
    const auditEntry = {
      action: 'create',
      timestamp: new Date().toISOString(),
      content,
      metadata
    };

    const signedDoc = await this.agent.createDocument(
      JSON.stringify({ ...content, _audit: auditEntry })
    );

    const doc = JSON.parse(signedDoc);

    // Save to audit log
    await this.logAuditEntry(doc.jacsId, 'create', doc);

    return doc;
  }

  async updateDocument(originalDoc, newContent, metadata = {}) {
    const auditEntry = {
      action: 'update',
      timestamp: new Date().toISOString(),
      previousVersion: originalDoc.jacsVersion,
      changes: this.computeChanges(originalDoc, newContent),
      metadata
    };

    const updatedDoc = await this.agent.updateDocument(
      JSON.stringify(originalDoc),
      JSON.stringify({ ...newContent, _audit: auditEntry })
    );

    const doc = JSON.parse(updatedDoc);

    // Save to audit log
    await this.logAuditEntry(doc.jacsId, 'update', doc);

    return doc;
  }

  computeChanges(original, updated) {
    const changes = [];

    for (const [key, value] of Object.entries(updated)) {
      if (key.startsWith('_')) continue;

      if (!(key in original)) {
        changes.push({ field: key, type: 'added', newValue: value });
      } else if (JSON.stringify(original[key]) !== JSON.stringify(value)) {
        changes.push({
          field: key,
          type: 'modified',
          oldValue: original[key],
          newValue: value
        });
      }
    }

    for (const key of Object.keys(original)) {
      if (key.startsWith('_') || key.startsWith('jacs')) continue;
      if (!(key in updated)) {
        changes.push({ field: key, type: 'removed', oldValue: original[key] });
      }
    }

    return changes;
  }

  async logAuditEntry(documentId, action, document) {
    const logFile = path.join(this.auditDir, `${documentId}.audit.jsonl`);

    const entry = {
      timestamp: new Date().toISOString(),
      action,
      documentId,
      version: document.jacsVersion,
      signature: document.jacsSignature,
      hash: document.jacsSha256
    };

    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  }

  async getAuditTrail(documentId) {
    const logFile = path.join(this.auditDir, `${documentId}.audit.jsonl`);

    if (!fs.existsSync(logFile)) {
      return [];
    }

    const lines = fs.readFileSync(logFile, 'utf-8').trim().split('\n');
    return lines.map(line => JSON.parse(line));
  }

  async verifyAuditTrail(documentId) {
    const trail = await this.getAuditTrail(documentId);
    const results = [];

    for (const entry of trail) {
      // Load and verify each version
      const docPath = path.join(
        this.auditDir,
        'documents',
        documentId,
        `${entry.version}.json`
      );

      if (fs.existsSync(docPath)) {
        const docString = fs.readFileSync(docPath, 'utf-8');
        const isValid = await this.agent.verifyDocument(docString);

        results.push({
          version: entry.version,
          timestamp: entry.timestamp,
          action: entry.action,
          valid: isValid
        });
      } else {
        results.push({
          version: entry.version,
          timestamp: entry.timestamp,
          action: entry.action,
          valid: null,
          error: 'Document file not found'
        });
      }
    }

    return results;
  }
}

// Usage
async function runAuditExample() {
  const audit = new AuditTrailSystem('./jacs.config.json');
  await audit.initialize();

  // Create a document
  const doc = await audit.createDocument({
    type: 'financial_report',
    period: 'Q1 2024',
    revenue: 1000000,
    expenses: 750000
  }, { author: 'Finance Team' });

  console.log('Created document:', doc.jacsId);

  // Update the document
  const updated = await audit.updateDocument(doc, {
    type: 'financial_report',
    period: 'Q1 2024',
    revenue: 1000000,
    expenses: 750000,
    profit: 250000,  // Added field
    status: 'approved'
  }, { author: 'CFO', reason: 'Added profit calculation' });

  console.log('Updated to version:', updated.jacsVersion);

  // Get audit trail
  const trail = await audit.getAuditTrail(doc.jacsId);
  console.log('Audit trail:');
  for (const entry of trail) {
    console.log(`  ${entry.timestamp} - ${entry.action} (v${entry.version})`);
  }
}

runAuditExample().catch(console.error);
```

## Multi-Tenant Document Service

A complete multi-tenant document service with isolated agents per tenant.

```python
# multi_tenant.py
import jacs
import json
import os
from pathlib import Path
from typing import Dict, Optional

class TenantManager:
    def __init__(self, base_dir: str = './tenants'):
        self.base_dir = Path(base_dir)
        self.agents: Dict[str, jacs.JacsAgent] = {}

    def initialize_tenant(self, tenant_id: str) -> dict:
        """Create a new tenant with its own JACS agent"""
        tenant_dir = self.base_dir / tenant_id
        data_dir = tenant_dir / 'data'
        key_dir = tenant_dir / 'keys'

        # Create directories
        data_dir.mkdir(parents=True, exist_ok=True)
        key_dir.mkdir(parents=True, exist_ok=True)

        # Create tenant config
        config = {
            "jacs_data_directory": str(data_dir),
            "jacs_key_directory": str(key_dir),
            "jacs_agent_key_algorithm": "ring-Ed25519",
            "jacs_default_storage": "fs"
        }

        config_path = tenant_dir / 'jacs.config.json'
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Initialize agent
        agent = jacs.JacsAgent()
        agent.load(str(config_path))
        self.agents[tenant_id] = agent

        return {
            "tenant_id": tenant_id,
            "config_path": str(config_path),
            "initialized": True
        }

    def get_agent(self, tenant_id: str) -> Optional[jacs.JacsAgent]:
        """Get the JACS agent for a tenant"""
        if tenant_id not in self.agents:
            # Try to load existing tenant
            config_path = self.base_dir / tenant_id / 'jacs.config.json'
            if config_path.exists():
                agent = jacs.JacsAgent()
                agent.load(str(config_path))
                self.agents[tenant_id] = agent

        return self.agents.get(tenant_id)

    def create_document(self, tenant_id: str, content: dict) -> dict:
        """Create a document for a tenant"""
        agent = self.get_agent(tenant_id)
        if not agent:
            raise ValueError(f"Tenant {tenant_id} not found")

        signed_doc = agent.create_document(json.dumps(content))
        return json.loads(signed_doc)

    def verify_document(self, tenant_id: str, doc_string: str) -> bool:
        """Verify a document for a tenant"""
        agent = self.get_agent(tenant_id)
        if not agent:
            raise ValueError(f"Tenant {tenant_id} not found")

        return agent.verify_document(doc_string)

    def list_tenants(self) -> list:
        """List all tenants"""
        if not self.base_dir.exists():
            return []

        return [
            d.name for d in self.base_dir.iterdir()
            if d.is_dir() and (d / 'jacs.config.json').exists()
        ]

class MultiTenantDocumentService:
    def __init__(self):
        self.tenant_manager = TenantManager()

    def create_tenant(self, tenant_id: str) -> dict:
        return self.tenant_manager.initialize_tenant(tenant_id)

    def create_document(self, tenant_id: str, content: dict) -> dict:
        doc = self.tenant_manager.create_document(tenant_id, content)

        # Save document
        tenant_dir = self.tenant_manager.base_dir / tenant_id / 'documents'
        tenant_dir.mkdir(parents=True, exist_ok=True)

        doc_path = tenant_dir / f"{doc['jacsId']}.json"
        with open(doc_path, 'w') as f:
            json.dump(doc, f, indent=2)

        return {
            "tenant_id": tenant_id,
            "document_id": doc['jacsId'],
            "version": doc['jacsVersion'],
            "path": str(doc_path)
        }

    def get_document(self, tenant_id: str, document_id: str) -> Optional[dict]:
        doc_path = (
            self.tenant_manager.base_dir / tenant_id /
            'documents' / f"{document_id}.json"
        )

        if not doc_path.exists():
            return None

        with open(doc_path, 'r') as f:
            return json.load(f)

    def verify_document(self, tenant_id: str, document_id: str) -> dict:
        doc = self.get_document(tenant_id, document_id)
        if not doc:
            return {"valid": False, "error": "Document not found"}

        is_valid = self.tenant_manager.verify_document(
            tenant_id, json.dumps(doc)
        )

        return {
            "tenant_id": tenant_id,
            "document_id": document_id,
            "valid": is_valid
        }

# Usage
if __name__ == "__main__":
    service = MultiTenantDocumentService()

    # Create tenants
    tenant1 = service.create_tenant("acme-corp")
    tenant2 = service.create_tenant("globex-inc")
    print(f"Created tenants: {tenant1['tenant_id']}, {tenant2['tenant_id']}")

    # Create documents for each tenant
    doc1 = service.create_document("acme-corp", {
        "type": "invoice",
        "amount": 5000,
        "customer": "John Doe"
    })
    print(f"Acme Corp document: {doc1['document_id']}")

    doc2 = service.create_document("globex-inc", {
        "type": "contract",
        "value": 100000,
        "parties": ["Globex", "Initech"]
    })
    print(f"Globex Inc document: {doc2['document_id']}")

    # Verify documents
    verify1 = service.verify_document("acme-corp", doc1['document_id'])
    verify2 = service.verify_document("globex-inc", doc2['document_id'])
    print(f"Acme Corp verification: {verify1['valid']}")
    print(f"Globex Inc verification: {verify2['valid']}")

    # Cross-tenant verification should fail
    cross = service.verify_document("acme-corp", doc2['document_id'])
    print(f"Cross-tenant verification: {cross}")
```

## Webhook Notification System

Notify external systems when documents are signed.

```javascript
// webhook-notifier.js
import { JacsAgent } from '@hai-ai/jacs';
import express from 'express';
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';

const app = express();
const PORT = 3000;

// Initialize JACS
const agent = new JacsAgent();
await agent.load('./jacs.config.json');

// Webhook configuration
const webhooks = new Map();

// Register a webhook
app.post('/webhooks', express.json(), (req, res) => {
  const { url, events, secret } = req.body;
  const webhookId = crypto.randomUUID();

  webhooks.set(webhookId, { url, events, secret, active: true });

  res.json({ webhookId, message: 'Webhook registered' });
});

// JACS-protected document endpoints
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

app.post('/api/documents', async (req, res) => {
  if (!req.jacsPayload) {
    return res.status(400).send({ error: 'Invalid JACS request' });
  }

  // Create document
  const signedDoc = await agent.createDocument(
    JSON.stringify(req.jacsPayload)
  );
  const doc = JSON.parse(signedDoc);

  // Notify webhooks
  await notifyWebhooks('document.created', {
    documentId: doc.jacsId,
    version: doc.jacsVersion,
    timestamp: new Date().toISOString()
  });

  res.send({
    success: true,
    documentId: doc.jacsId
  });
});

async function notifyWebhooks(event, payload) {
  for (const [id, webhook] of webhooks) {
    if (!webhook.active) continue;
    if (!webhook.events.includes(event) && !webhook.events.includes('*')) continue;

    try {
      // Sign the webhook payload with JACS
      const signedPayload = await agent.signRequest({
        event,
        payload,
        timestamp: new Date().toISOString(),
        webhookId: id
      });

      // Send webhook
      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'X-JACS-Signature': 'v1',
          'X-Webhook-Secret': webhook.secret
        },
        body: signedPayload
      });

      if (!response.ok) {
        console.error(`Webhook ${id} failed: ${response.status}`);
      }
    } catch (error) {
      console.error(`Webhook ${id} error:`, error.message);
    }
  }
}

app.listen(PORT, () => {
  console.log(`Webhook notification server running on port ${PORT}`);
});
```

## See Also

- [CLI Examples](cli.md) - Command-line examples
- [Node.js Examples](nodejs.md) - Node.js code examples
- [Python Examples](python.md) - Python code examples
- [MCP Integration](../integrations/mcp.md) - MCP details
- [Web Servers](../integrations/web-servers.md) - HTTP integration
