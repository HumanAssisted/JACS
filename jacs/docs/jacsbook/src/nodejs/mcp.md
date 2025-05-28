# Model Context Protocol (MCP) Integration

JACS provides native integration with the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), enabling secure agent communication within AI systems. This allows JACS agents to be used directly as MCP servers or clients.

## What is MCP?

Model Context Protocol is a standard for AI models to securely access external tools, data, and services. JACS enhances MCP by adding:

- **Cryptographic verification** of tool outputs
- **Agent identity** for all operations
- **Audit trails** of all MCP interactions
- **Multi-agent agreements** for complex workflows

## Quick Start

### Basic MCP Server

```javascript
import { JacsMcpServer } from 'jacsnpm/mcp';

// Create a JACS-enabled MCP server
const server = new JacsMcpServer({
  name: "JACS Task Server",
  version: "1.0.0",
  configPath: './jacs.config.json'
});

// Add JACS tools automatically
server.addJacsTools();

// Start the server
await server.start();
console.log('JACS MCP Server running!');
```

### Using with Existing MCP Server

```javascript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createJacsMiddleware } from 'jacsnpm/mcp';

const server = new McpServer({ 
  name: "MyServer", 
  version: "1.0.0" 
});

// Add JACS middleware
server.use(createJacsMiddleware({ 
  configPath: './jacs.config.json' 
}));

await server.start();
```

## Available Tools

When you add JACS to an MCP server, it provides these tools:

### Agent Management
- `jacs_create_agent` - Create new JACS agents
- `jacs_update_agent` - Update agent information
- `jacs_verify_agent` - Verify agent signatures
- `jacs_list_agents` - List all known agents

### Task Management  
- `jacs_create_task` - Create signed task documents
- `jacs_assign_task` - Delegate tasks to other agents
- `jacs_complete_task` - Mark tasks as completed
- `jacs_verify_task` - Verify task signatures

### Agreement Management
- `jacs_create_agreement` - Create multi-party agreements
- `jacs_sign_agreement` - Add signature to agreement
- `jacs_verify_agreement` - Check agreement completeness
- `jacs_list_agreements` - Show pending/completed agreements

### Document Operations
- `jacs_create_document` - Create and sign any document
- `jacs_verify_document` - Verify document integrity
- `jacs_list_documents` - List all documents
- `jacs_get_document` - Retrieve specific document

## Configuration

### Server Configuration

```javascript
const serverConfig = {
  // MCP Server settings
  name: "JACS Agent Server",
  version: "1.0.0",
  
  // JACS Configuration
  configPath: './jacs.config.json',
  
  // Optional: Custom tools
  enabledTools: [
    'jacs_create_task',
    'jacs_verify_task', 
    'jacs_create_agreement',
    'jacs_sign_agreement'
  ],
  
  // Optional: Auto-initialization
  autoInit: true,
  createAgentOnInit: true
};

const server = new JacsMcpServer(serverConfig);
```

### Middleware Configuration

```javascript
const middlewareConfig = {
  configPath: './jacs.config.json',
  
  // Agent initialization
  autoCreateAgent: true,
  agentName: "MCP JACS Agent",
  agentDescription: "Agent providing JACS services via MCP",
  
  // Tool selection
  tools: ['tasks', 'agreements', 'documents'],
  
  // Security options
  requireSignatures: true,
  verifyIncomingDocuments: true
};

server.use(createJacsMiddleware(middlewareConfig));
```

## Tool Usage Examples

### Creating a Task

```javascript
// MCP Client code (Claude, other AI systems)
const taskResult = await mcpClient.callTool('jacs_create_task', {
  title: "Analyze Sales Data",
  description: "Generate insights from Q4 sales data",
  actions: [
    {
      id: "extract",
      name: "Extract Data",
      description: "Pull sales data from database",
      success: "Complete dataset extracted",
      failure: "Unable to connect to database"
    },
    {
      id: "analyze", 
      name: "Analyze Trends",
      description: "Identify patterns and insights",
      success: "Key insights identified",
      failure: "Insufficient data for analysis"
    }
  ]
});

console.log('Task created:', taskResult.jacsId);
console.log('Task signature:', taskResult.jacsSignature);
```

### Creating an Agreement

```javascript
const agreementResult = await mcpClient.callTool('jacs_create_agreement', {
  title: "Data Analysis Agreement",
  question: "Do you agree to analyze the Q4 sales data?",
  context: "Task requires access to confidential sales database",
  agents: [
    "agent-1-uuid",
    "agent-2-uuid",
    "agent-3-uuid"
  ]
});

console.log('Agreement created:', agreementResult.jacsId);
console.log('Required signatures:', agreementResult.agents.length);
```

### Verifying Documents

```javascript
const verificationResult = await mcpClient.callTool('jacs_verify_document', {
  documentId: "task-uuid-here"
});

console.log('Document valid:', verificationResult.valid);
console.log('Signature verified:', verificationResult.signatureValid);
console.log('Hash verified:', verificationResult.hashValid);
```

## Advanced Integration

### Custom Tools

Add your own JACS-aware tools:

```javascript
import { JacsMcpServer } from 'jacsnpm/mcp';

const server = new JacsMcpServer(config);

// Custom tool that creates signed reports
server.addTool({
  name: "create_signed_report",
  description: "Create a cryptographically signed report",
  inputSchema: {
    type: "object",
    properties: {
      title: { type: "string" },
      content: { type: "string" },
      reportType: { type: "string", enum: ["analysis", "summary", "recommendation"] }
    },
    required: ["title", "content", "reportType"]
  }
}, async (params) => {
  const { title, content, reportType } = params;
  
  // Create report document
  const report = {
    jacsType: "report",
    title,
    content,
    reportType,
    generatedAt: new Date().toISOString()
  };
  
  // Sign with JACS agent
  const signedReport = await server.jacsAgent.createDocument(report);
  
  return {
    success: true,
    document: signedReport,
    verification: await server.jacsAgent.verifyDocument(signedReport)
  };
});
```

### Multi-Agent Workflows

Coordinate multiple agents through MCP:

```javascript
// Agent A creates a task
const task = await agentA.callTool('jacs_create_task', {
  title: "Content Creation Pipeline",
  description: "Multi-stage content creation process"
});

// Create agreement for collaboration
const agreement = await agentA.callTool('jacs_create_agreement', {
  title: "Content Collaboration Agreement", 
  question: "Do you agree to participate in content creation?",
  context: `Task: ${task.jacsId}`,
  agents: [agentA.id, agentB.id, agentC.id]
});

// Each agent signs the agreement
await agentA.callTool('jacs_sign_agreement', { agreementId: agreement.jacsId });
await agentB.callTool('jacs_sign_agreement', { agreementId: agreement.jacsId });
await agentC.callTool('jacs_sign_agreement', { agreementId: agreement.jacsId });

// Verify all signatures before proceeding
const verification = await agentA.callTool('jacs_verify_agreement', { 
  agreementId: agreement.jacsId 
});

if (verification.complete) {
  console.log('All agents have signed - workflow can proceed');
}
```

## Transport Options

### Stdio Transport (Default)

```javascript
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new JacsMcpServer(config);
const transport = new StdioServerTransport();
await server.connect(transport);
```

### SSE Transport (HTTP)

```javascript
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

const server = new JacsMcpServer(config);
const transport = new SSEServerTransport('/mcp', {
  port: 3000
});
await server.connect(transport);
```

### WebSocket Transport

```javascript
import { WebSocketServerTransport } from '@modelcontextprotocol/sdk/server/websocket.js';

const server = new JacsMcpServer(config);
const transport = new WebSocketServerTransport({
  port: 3001
});
await server.connect(transport);
```

## Client Integration

### Using JACS with MCP Clients

```javascript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// Connect to JACS MCP server
const transport = new StdioClientTransport({
  command: 'node',
  args: ['jacs-mcp-server.js']
});

const client = new Client({
  name: "JACS MCP Client",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

await client.connect(transport);

// List available JACS tools
const tools = await client.listTools();
console.log('Available JACS tools:', tools.tools.map(t => t.name));

// Use JACS tools
const result = await client.callTool({
  name: "jacs_create_task",
  arguments: {
    title: "Example Task",
    description: "Task created via MCP client"
  }
});

console.log('Task created:', result.content);
```

## Security Considerations

### Signature Verification

All JACS tools automatically verify signatures:

```javascript
// Tool implementation with verification
server.addTool({
  name: "process_task_result",
  description: "Process results from task completion"
}, async (params) => {
  const { taskId, result } = params;
  
  // Verify the task exists and signature is valid
  const task = await server.jacsAgent.getDocument(taskId);
  const isValid = await server.jacsAgent.verifyDocument(task);
  
  if (!isValid) {
    throw new Error('Invalid task signature - refusing to process');
  }
  
  // Process the verified task result
  return processResult(result);
});
```

### Agent Authentication

Authenticate agent identity for sensitive operations:

```javascript
server.addTool({
  name: "access_sensitive_data",
  description: "Access sensitive data with agent verification"
}, async (params, context) => {
  const { agentId, dataType } = params;
  
  // Verify the requesting agent has proper credentials
  const agent = await server.jacsAgent.getAgent(agentId);
  const hasPermission = await checkAgentPermissions(agent, dataType);
  
  if (!hasPermission) {
    throw new Error('Agent lacks permission for this data type');
  }
  
  return getSensitiveData(dataType);
});
```

## Monitoring and Observability

### Request Logging

```javascript
const server = new JacsMcpServer({
  ...config,
  logging: {
    logRequests: true,
    logSignatures: true,
    logVerifications: true
  }
});

// Logs will include:
// - Tool calls with agent identity
// - Signature verification results  
// - Document creation/modification
// - Agreement signing events
```

### Metrics Collection

```javascript
import { recordMcpOperation } from 'jacsnpm/observability';

server.addTool({
  name: "example_tool"
}, async (params) => {
  const startTime = Date.now();
  
  try {
    const result = await performOperation(params);
    
    recordMcpOperation('example_tool', true, Date.now() - startTime);
    return result;
  } catch (error) {
    recordMcpOperation('example_tool', false, Date.now() - startTime);
    throw error;
  }
});
```

## Examples

Complete MCP integration examples are available:

- **[Basic MCP Server](../examples/nodejs.md#mcp-server)** - Simple JACS MCP server
- **[Express Integration](../examples/nodejs.md#express-mcp)** - MCP server with Express.js
- **[Multi-Agent Workflow](../examples/nodejs.md#multi-agent-mcp)** - Coordinated agent collaboration
- **[Custom Tools](../examples/nodejs.md#custom-mcp-tools)** - Building domain-specific JACS tools

## Troubleshooting

### Connection Issues

```bash
# Test MCP server connectivity
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}' | node jacs-mcp-server.js
```

### Tool Registration Problems

```javascript
// Verify tools are registered correctly
const server = new JacsMcpServer(config);
await server.start();

const tools = await server.listTools();
console.log('Registered tools:', tools.map(t => t.name));
```

### Signature Verification Failures

```javascript
// Debug signature issues
try {
  const result = await mcpClient.callTool('jacs_verify_document', {
    documentId: 'problematic-doc-id'
  });
} catch (error) {
  console.error('Verification details:', error.details);
  // Check agent keys, document integrity, etc.
}
```

For more details, see the [API Reference](api.md) and [complete examples](../examples/nodejs.md). 