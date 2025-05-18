// JACS/jacsnpm/examples/mcp.sse.server.js
// console.log(`SPAWNED_SERVER_LOG: Original mcp.server.js starting. CWD: ${process.cwd()}. Timestamp: ${new Date().toISOString()}`);
// console.error(`SPAWNED_SERVER_ERROR_LOG: Original mcp.server.js starting. Timestamp: ${new Date().toISOString()}`);e

import { JacsMcpServer } from '../mcp.js';
// ResourceTemplate and z are not directly used here anymore,
// as tools/resources are registered on the JacsMcpServer instance itself.
import * as http from 'node:http';
import { URL } from 'node:url'; // Ensure URL is imported

const serverConfigPath = "./jacs.server.config.json";
const PORT = 3000;
const SSE_PATH = "/sse"; // Path for initiating SSE connection

// --- Create and configure a single JacsMcpServer instance ---
const mcpServer = new JacsMcpServer({
    name: "my-main-sse-server",
    version: "1.0.0",
    configPath: serverConfigPath,
    transportType: 'sse', // Explicitly configure for SSE
    sseConfig: {
        // postEndpoint: '/mcp_message_handler' // Optional: if you want to customize the POST path.
                                             // Default in JacsMcpServer.handleSseRequest is '/mcp-sse-post'
                                             // Let's use the default from JacsMcpServer for now.
    }
});

// --- Register tools and resources on this single server instance ---
// (Copied from your previous JacsMcpServer instantiation in mcp.js)
import { z } from "zod"; // Make sure zod is imported if not already
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";


mcpServer.tool("add",
    { a: z.number(), b: z.number() },
    async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] })
);

mcpServer.resource("greeting",
    new ResourceTemplate("greeting://{name}", { list: undefined }),
    async (uri, { name }) => ({ contents: [{ uri: uri.href, text: `Hello, ${name}!` }] })
);

// --- Connect the main JacsMcpServer ---
// For SSE mode where transports are dynamic per client,
// this initial connect() call might primarily be for initializing
// the server's internal router and JACS agent, not for a specific transport.
// The JacsMcpServer.connect method needs to handle this gracefully if transportType is 'sse'.
// Based on JacsMcpServer's current connect, it will try to load JACS.
// If no default transport is found (which is the case for 'sse' type before handleSseRequest),
// it might error if it expects one. Let's assume it's handled or we'll adjust JacsMcpServer.connect later.
async function initializeServer() {
    try {
        console.log("Initializing main JacsMcpServer for SSE handling...");
        await mcpServer.connect(); // Connects the server logic, loads JACS
        console.log("Main JacsMcpServer initialized and connected (JACS loaded).");
    } catch (error) {
        console.error("Failed to initialize main JacsMcpServer:", error);
        process.exit(1);
    }
}

const httpServer = http.createServer(async (req, res) => {
  console.log(`HTTP Server: Received ${req.method} request for ${req.url}`);
  const requestUrl = new URL(req.url, `http://${req.headers.host}`);

  // CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*', 
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    });
    return res.end();
  }
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method === 'GET' && requestUrl.pathname === SSE_PATH) {
    console.log(`HTTP Server: Routing GET to mcpServer.handleSseRequest for ${SSE_PATH}`);
    await mcpServer.handleSseRequest(req, res);
  } 
  // Match the POST path that SSEServerTransport internally constructs and sends to client.
  // Default in JacsMcpServer.handleSseRequest -> SSEServerTransport constructor is '/mcp-sse-post'.
  else if (req.method === 'POST' && requestUrl.pathname === (mcpServer.sseConfig?.postEndpoint || '/mcp-sse-post')) {
    console.log(`HTTP Server: Routing POST to mcpServer.handleSsePost for ${requestUrl.pathname}`);
    await mcpServer.handleSsePost(req, res);
  } else {
    console.log(`HTTP Server: Unhandled request: ${req.method} ${requestUrl.pathname}`);
    res.writeHead(404).end("Not Found");
  }
});

initializeServer().then(() => {
    httpServer.listen(PORT, () => {
        console.log(`SSE MCP Server Example (using JacsMcpServer methods) listening on http://localhost:${PORT}`);
        console.log(`Clients connect to SSE stream at http://localhost:${PORT}${SSE_PATH}`);
        console.log(`Clients will be directed to POST messages to a path like /mcp-sse-post?sessionId=...`);
    });
}).catch(err => {
    console.error("Failed to start HTTP server due to initialization error:", err);
    process.exit(1);
});