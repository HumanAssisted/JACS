// JACS/jacsnpm/examples/mcp.sse.server.js
// console.log(`SPAWNED_SERVER_LOG: Original mcp.server.js starting. CWD: ${process.cwd()}. Timestamp: ${new Date().toISOString()}`);
// console.error(`SPAWNED_SERVER_ERROR_LOG: Original mcp.server.js starting. Timestamp: ${new Date().toISOString()}`);e

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { createJACSTransportProxy } from '../mcp.js';
import * as http from 'node:http';
import { URL } from 'node:url';
// import { z } from "zod"; // Not needed for the simplified tool
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import express from 'express'; // Import express

const serverConfigPath = "./jacs.server.config.json";
const PORT = 3000;
const SSE_PATH = "/sse";
const MCP_POST_PATH = '/mcp-sse-post'; // Define the post path

// Function to create and configure a new McpServer instance
async function createAndConfigureMcpServer() {
  console.log('[MCP_SERVER_FACTORY] Creating new McpServer instance...');
  const server = new McpServer({
    name: "my-main-sse-server", // Name can be the same
    version: "1.0.0"
  });
  console.log('[MCP_SERVER_FACTORY] McpServer instance created.');

  server.onResponse = (response) => {
    const responseId = response && typeof response === 'object' && 'id' in response ? response.id : 'N/A';
    // Add a way to know WHICH server instance this is if debugging multiple concurrent connections
    console.log(`[MCP_SERVER_EVENT] server.onResponse: ID=${responseId}, Full Response: ${JSON.stringify(response).substring(0, 300)}...`);
  };

  // Register tools and resources
  console.log('[MCP_SERVER_FACTORY] Registering simplified tool: simpleTool on new server instance');
  server.tool(
      "simpleTool",
      {}, 
      async () => {
        console.log(`[MCP_TOOL_CALL] Tool 'simpleTool' called`);
        return { content: [{ type: "text", text: "Simple tool executed" }] };
      }
  );
  console.log('[MCP_SERVER_FACTORY] Tool "simpleTool" registered on new server instance.');

  server.tool("add", {
    a: { type: "number", description: "First number" },
    b: { type: "number", description: "Second number" }
  }, async ({ a, b }) => {
    console.log(`[MCP_TOOL_CALL] Tool 'add' called with a=${a}, b=${b}`);
    return { content: [{ type: "text", text: `${a} + ${b} = ${a + b}` }] };
  });

  // Resource registration (optional for this test, can be kept commented)
  // console.log('[MCP_SERVER_FACTORY] Registering resource: greeting on new server instance');
  // server.resource("greeting", ...);
  // console.log('[MCP_SERVER_FACTORY] Resource "greeting" registered on new server instance.');

  try {
    console.log('[MCP_SERVER_FACTORY] Setting tool request handlers on new server instance...');
    await server.setToolRequestHandlers();
    console.log('[MCP_SERVER_FACTORY] Tool request handlers SET on new server instance.');

    console.log('[MCP_SERVER_FACTORY] Setting resource request handlers on new server instance...');
    await server.setResourceRequestHandlers();
    console.log('[MCP_SERVER_FACTORY] Resource request handlers SET on new server instance.');
  } catch (error) {
    console.error('[MCP_SERVER_FACTORY] CRITICAL ERROR during handler setup on new server instance:', error);
    throw error; // Rethrow to prevent use of misconfigured server
  }
  return server;
}

const sseTransportsAndServers = new Map(); // Store { transport, mcpServerInstance }

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
  console.log(`[HTTP_ROUTER] Received ${req.method} request for ${req.url}`);
  const requestUrl = new URL(req.url, `http://${req.headers.host}`);

  // CORS setup
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*', 
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-session-id, last-event-id',
      'Access-Control-Max-Age': '86400'
    });
    return res.end();
  }
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Handle GET request to establish SSE connection
  if (req.method === 'GET' && requestUrl.pathname === SSE_PATH) {
    console.log(`[HTTP_ROUTER] SSE connection request for ${SSE_PATH}`);
    const sseTransport = new SSEServerTransport(MCP_POST_PATH, res); 
    const currentSessionId = sseTransport.sessionId;
    console.log(`[HTTP_ROUTER] SSEServerTransport created for session: ${currentSessionId}`);
    
    console.log(`[HTTP_ROUTER] Creating JACS middleware for session: ${currentSessionId}`);
    // Use the synchronous factory for JACS transport
    const secureJacsTransport = createJACSTransportProxy(sseTransport, serverConfigPath, "server");
    console.log(`[HTTP_ROUTER] JACS middleware created for session: ${currentSessionId}`);
    
    try {
      // Create a NEW McpServer instance for this session
      const mcpServerInstance = await createAndConfigureMcpServer();
      
      // The originalConnect override needs to be on this specific instance if we want its logging
      // This is tricky because createAndConfigureMcpServer already makes 'server'.
      // For now, the global 'server.onResponse' will catch responses if they happen.

      console.log(`[HTTP_ROUTER] Connecting new McpServer instance to JACS middleware for session: ${currentSessionId}`);
      // Ensure the onmessage of the JACS transport is set to the mcpServerInstance's handler.
      // The JACS middleware constructor sets `this.transport.onmessage` to its own wrapper,
      // which then calls `this.onmessage`. So, `secureJacsTransport.onmessage` (the SDK's handler)
      // needs to be set to the `mcpServerInstance.handleRequest` (or equivalent).
      // The `mcpServerInstance.connect(secureJacsTransport)` should handle this by setting
      // `secureJacsTransport.onmessage` to its internal request processing logic.

      await mcpServerInstance.connect(secureJacsTransport); 
      console.log(`[HTTP_ROUTER] New McpServer instance connected to JACS middleware for session: ${currentSessionId}`);
      
      sseTransportsAndServers.set(currentSessionId, { transport: secureJacsTransport, server: mcpServerInstance });
      console.log(`[HTTP_ROUTER] Stored JACS middleware and McpServer for session: ${currentSessionId}. Total sessions: ${sseTransportsAndServers.size}`);
      console.log(`[HTTP_ROUTER] Session ${currentSessionId} is ready.`);

      // Clean up when client disconnects
      sseTransport.onclose = () => { // Note: using underlying sseTransport.onclose
        console.log(`[HTTP_ROUTER] SSE transport closed for session ${currentSessionId}. Cleaning up.`);
        sseTransportsAndServers.delete(currentSessionId);
        // We might want to call mcpServerInstance.close() if it has resources
      };

    } catch (error) {
        console.error(`[HTTP_ROUTER] CRITICAL ERROR during McpServer instantiation, handler setup, or connect for session ${currentSessionId}:`, error);
        if (!res.headersSent && !res.writableEnded) {
            res.writeHead(500).end("Server setup error");
        }
    }

    // SSE transport handles keeping the connection open, so no `res.end()` here from Express.
  } 
  // Handle POST requests (messages from client)
  else if (req.method === 'POST' && requestUrl.pathname === MCP_POST_PATH) {
    const sessionId = requestUrl.searchParams.get('sessionId');
    console.log(`[HTTP_ROUTER] POST request for session ${sessionId}. Path: ${MCP_POST_PATH}. Available sessions: ${Array.from(sseTransportsAndServers.keys()).join(', ')}`);
    
    const sessionData = sseTransportsAndServers.get(sessionId);
    if (!sessionData || !sessionData.transport) {
      console.error(`[HTTP_ROUTER] Session ${sessionId} or its transport NOT FOUND for POST request.`);
      res.writeHead(404).end("Session not found");
      return;
    }
    
    const transportToUse = sessionData.transport; // This is the JACS TransportMiddleware instance
    console.log(`[HTTP_ROUTER] Found JACS middleware for POST to session ${sessionId}. Has handlePostMessage: ${typeof transportToUse.handlePostMessage === 'function'}`);
    
    try {
      // The JACS TransportMiddleware's onmessage is already wired to the specific McpServer instance's handler by mcpServerInstance.connect()
      await transportToUse.handlePostMessage(req, res, req.body); 
      console.log(`[HTTP_ROUTER] Successfully processed POST message via JACS middleware for session ${sessionId}`);
    } catch (error) {
      console.error(`[HTTP_ROUTER] Error processing POST via JACS middleware for session ${sessionId}: ${error.message}`, error);
      if (!res.writableEnded) {
        res.writeHead(500).end(`Error: ${error.message}`);
      }
    }
  } else {
    console.log(`[HTTP_ROUTER] Unhandled path: ${req.method} ${requestUrl.pathname}. Passing to next().`);
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
