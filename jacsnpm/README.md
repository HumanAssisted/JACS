# JACS Node.js Library

Node.js bindings for JACS (JSON Agent Communication Standard) with A2A protocol support.

```bash
npm install jacsnpm
```

## Quick Start

```javascript
const jacs = require('jacsnpm');

// Load JACS configuration
jacs.load('jacs.config.json');

// Sign and verify documents
const signedDoc = jacs.signRequest({ data: 'value' });
const isValid = jacs.verifyResponse(signedDoc);
```

## A2A Protocol Integration

JACS Node.js includes support for Google's A2A (Agent-to-Agent) protocol:

```javascript
const { JACSA2AIntegration } = require('jacsnpm');

// Initialize A2A integration
const a2a = new JACSA2AIntegration('jacs.config.json');

// Export JACS agent to A2A Agent Card
const agentCard = a2a.exportAgentCard(agentData);

// Wrap A2A artifacts with JACS provenance
const wrapped = a2a.wrapArtifactWithProvenance(artifact, 'task');

// Verify wrapped artifacts
const result = a2a.verifyWrappedArtifact(wrapped);

// Create chain of custody for workflows
const chain = a2a.createChainOfCustody([wrapped1, wrapped2, wrapped3]);
```

See [examples/a2a-agent-example.js](./examples/a2a-agent-example.js) for a complete example.

## Usage 

see [examples](./examples)

### With MCP

You can use JACS middleware

```js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createJacsMiddleware } from 'jacsnpm/mcp';

const server = new McpServer({ name: "MyServer", version: "1.0.0" });
server.use(createJacsMiddleware({ configPath: './config.json' }));
```

Or you can use JACS warpper for simpler syntax

```js
import { JacsMcpServer } from 'jacsnpm/mcp';

const server = new JacsMcpServer({
    name: "MyServer",
    version: "1.0.0",
    configPath: './config.json'
});
```