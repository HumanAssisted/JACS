// JACS/jacsnpm/examples/mcp.sse.server.js
// console.log(`SPAWNED_SERVER_LOG: Original mcp.server.js starting. CWD: ${process.cwd()}. Timestamp: ${new Date().toISOString()}`);
// console.error(`SPAWNED_SERVER_ERROR_LOG: Original mcp.server.js starting. Timestamp: ${new Date().toISOString()}`);e

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { createJacsMiddleware } from '../mcp.js';
import * as http from 'node:http';
import { URL } from 'node:url';
import { z } from "zod";
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";

const serverConfigPath = "./jacs.server.config.json";
const PORT = 3000;
const SSE_PATH = "/sse";

// Create a standard McpServer
const server = new McpServer({
    name: "my-main-sse-server",
    version: "1.0.0"
});

// Register tools and resources
server.tool("add",
    { a: z.number(), b: z.number() },
    async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] })
);

server.resource("greeting",
    new ResourceTemplate("greeting://{name}", { list: undefined }),
    async (uri, { name }) => ({ contents: [{ uri: uri.href, text: `Hello, ${name}!` }] })
);

// Set up session mapping for SSE connections
const sseTransports = new Map();

const httpServer = http.createServer(async (req, res) => {
  console.log(`HTTP Server: Received ${req.method} request for ${req.url}`);
  const requestUrl = new URL(req.url, `http://${req.headers.host}`);

  // CORS setup
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

  // Handle GET request to establish SSE connection
  if (req.method === 'GET' && requestUrl.pathname === SSE_PATH) {
    const sseTransport = new SSEServerTransport("/mcp-sse-post", res);
    
    // Create middleware-wrapped transport
    const secureTransport = createJacsMiddleware(sseTransport, serverConfigPath);
    
    // Store the transport for later POST requests
    sseTransports.set(sseTransport.sessionId, secureTransport);
    
    // Connect server to this transport - this automatically starts the transport
    await server.connect(secureTransport);
  } 
  // Handle POST requests (messages from client)
  else if (req.method === 'POST' && requestUrl.pathname === '/mcp-sse-post') {
    const sessionId = requestUrl.searchParams.get('sessionId');
    console.log(`Processing POST for session ${sessionId}, available sessions: ${Array.from(sseTransports.keys()).join(', ')}`);
    
    if (!sessionId || !sseTransports.has(sessionId)) {
      console.error(`Session ${sessionId} not found`);
      res.writeHead(404).end("Session not found");
      return;
    }
    
    const transport = sseTransports.get(sessionId);
    console.log(`Found transport for session ${sessionId}, has handlePostMessage: ${typeof transport.handlePostMessage === 'function'}`);
    
    try {
      await transport.handlePostMessage(req, res);
      console.log(`Successfully processed POST message for session ${sessionId}`);
    } catch (error) {
      console.error(`Error processing POST: ${error.message}`);
      res.writeHead(500).end(`Error: ${error.message}`);
    }
  } else {
    res.writeHead(404).end("Not Found");
  }
});

httpServer.listen(PORT, () => {
  console.log(`SSE MCP Server with JACS middleware listening on http://localhost:${PORT}`);
  console.log(`Clients connect to SSE stream at http://localhost:${PORT}${SSE_PATH}`);
  console.log(`Clients will be directed to POST messages to /mcp-sse-post?sessionId=...`);
});
