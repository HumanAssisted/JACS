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
import express from 'express'; // Import express

const serverConfigPath = "./jacs.server.config.json";
const PORT = 3000;
const SSE_PATH = "/sse";
const MCP_POST_PATH = '/mcp-sse-post'; // Define the post path

// Create a standard McpServer
const server = new McpServer({
    name: "my-main-sse-server",
    version: "1.0.0"
});

server.onResponse = (response) => {
  console.log('Server generating response:', JSON.stringify(response));
};

// After creating the server
const originalConnect = server.connect.bind(server);
server.connect = async (transport) => {
  console.log('Server connecting to transport...');
  
  // Intercept messages at the server level
  const originalOnMessage = transport.onmessage;
  transport.onmessage = (msg) => {
    console.log('Server transport received:', JSON.stringify(msg).substring(0, 200));
    if (originalOnMessage) {
      const result = originalOnMessage(msg);
      console.log('Server processed message, result:', result);
      return result;
    }
  };
  
  return originalConnect(transport);
};

// Override the server's request handler to log what's happening
const originalHandler = server.handle?.bind(server) || server.handleRequest?.bind(server);
if (originalHandler) {
  server.handle = async (request) => {
    console.log('Server.handle called with:', JSON.stringify(request));
    const result = await originalHandler(request);
    console.log('Server.handle returning:', JSON.stringify(result));
    return result;
  };
}

// Also check if there's a specific method we need to enable
console.log('Server methods:', Object.getOwnPropertyNames(server));
console.log('Server prototype methods:', Object.getOwnPropertyNames(Object.getPrototypeOf(server)));

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

// Create an Express app to handle requests
const app = express();

// Middleware to get raw body as text for the JACS POST route
// This MUST come before any other middleware that might parse JSON for this route.
app.use(MCP_POST_PATH, express.text({ type: '*/*' })); // Ensures req.body is a string for JACS

// If you need a global JSON parser for other routes, define it after specific text parser
// app.use(express.json()); // For other non-JACS routes if needed

const httpServer = http.createServer(app); // Use the Express app for the HTTP server

app.use(async (req, res, next) => {
  // This middleware function will wrap the original http.createServer callback logic
  console.log(`HTTP Server (Express): Received ${req.method} request for ${req.url}`);
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
    // SSEServerTransport requires the raw response object, not an Express one if it modifies it too much.
    // We might need to manually manage the response object for SSE if Express wrapping interferes.
    // For now, let's assume SSEServerTransport can work with the Node `res` object even when passed through Express.
    const sseTransport = new SSEServerTransport(MCP_POST_PATH, res); 
    
    const secureTransport = createJacsMiddleware(sseTransport, serverConfigPath, "server");
    
    sseTransports.set(sseTransport.sessionId, secureTransport);
    
    await server.connect(secureTransport);

    try {
      await server.setToolRequestHandlers();
      await server.setResourceRequestHandlers();
      console.log('Request handlers initialized for session');
    } catch (error) {
        console.error('Failed to initialize handlers:', error);
    }

    // SSE transport handles keeping the connection open, so no `res.end()` here from Express.
  } 
  // Handle POST requests (messages from client)
  else if (req.method === 'POST' && requestUrl.pathname === MCP_POST_PATH) {
    const sessionId = requestUrl.searchParams.get('sessionId');
    console.log(`Processing POST for session ${sessionId}, available sessions: ${Array.from(sseTransports.keys()).join(', ')}`);
    
    if (!sessionId || !sseTransports.has(sessionId)) {
      console.error(`Session ${sessionId} not found`);
      res.writeHead(404).end("Session not found");
      return;
    }
    
    const transportToUse = sseTransports.get(sessionId); // This is our TransportMiddleware instance
    console.log(`Found transport for session ${sessionId}, has handlePostMessage: ${typeof transportToUse.handlePostMessage === 'function'}`);
    
    try {
      // req.body is now the raw string due to express.text() for this route.
      // Pass it as the third argument to handlePostMessage.
      await transportToUse.handlePostMessage(req, res, req.body); 
      // handlePostMessage in TransportMiddleware will now call res.end() or res.writeHead().end()
      console.log(`Successfully processed POST message for session ${sessionId}`);
    } catch (error) {
      console.error(`Error processing POST: ${error.message}`);
      if (!res.writableEnded) {
        res.writeHead(500).end(`Error: ${error.message}`);
      }
    }
  } else {
    // If not handled by SSE or MCP POST, let Express handle it or send 404
    next();
  }
});

// Fallback 404 for anything not caught by specific routes
app.use((req, res) => {
  if (!res.headersSent) {
    res.status(404).send('Not Found. Try GET /sse or POST /mcp-sse-post?sessionId=...');
  }
});

httpServer.listen(PORT, () => {
  console.log(`SSE MCP Server with JACS middleware listening on http://localhost:${PORT}`);
  console.log(`Clients connect to SSE stream at http://localhost:${PORT}${SSE_PATH}`);
  console.log(`Clients will be directed to POST messages to ${MCP_POST_PATH}?sessionId=...`);
});
