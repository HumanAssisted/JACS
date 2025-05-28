#!/usr/bin/env node
/**
 * MCP Server with JACS encryption using STDIO transport
 * CRITICAL: All logging must go to stderr, stdout is reserved for JSON-RPC
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJACSTransportProxy } from '../mcp.js';
import { z } from 'zod';

const SERVER_CONFIG_PATH = "./jacs.server.config.json";

async function main() {
  // ALL SERVER LOGS MUST GO TO STDERR (NOT STDOUT)
  console.error("JACS STDIO MCP Server starting...");
  
  try {
    // Disable JACS debugging to prevent stdout contamination
    process.env.JACS_MCP_DEBUG = "false";
    
    // Create the base STDIO transport
    const baseTransport = new StdioServerTransport();
    console.error("StdioServerTransport created");
    
    // Wrap with JACS encryption
    const secureTransport = createJACSTransportProxy(
      baseTransport,
      SERVER_CONFIG_PATH, 
      "server"
    );
    console.error("JACS transport proxy created");
    
    // Create and configure MCP server
    const server = new McpServer({
      name: "jacs-stdio-server",
      version: "1.0.0"
    });
    
    // Register tools with proper Zod schemas
    server.registerTool("add", {
      description: "Adds two numbers together",
      inputSchema: {
        a: z.number().describe("First number"),
        b: z.number().describe("Second number")
      }
    }, async ({ a, b }) => {
      console.error(`[JACS_STDIO_SERVER] Tool 'add' called with a=${a}, b=${b}`);
      return { content: [{ type: "text", text: `${a} + ${b} = ${a + b}` }] };
    });
    
    server.tool("echo", {
      message: z.string().describe("Message to echo")
    }, async ({ message }) => {
      console.error(`[JACS_STDIO_SERVER] Tool 'echo' called with message="${message}"`);
      return { content: [{ type: "text", text: `Echo: ${message}` }] };
    });
    
    // Register a simple resource
    server.resource(
      "server-info",
      "info://server",
      async (uri) => {
        console.error(`[JACS_STDIO_SERVER] Resource 'server-info' read`);
        return {
          contents: [{
            uri: uri.href,
            text: `JACS-secured STDIO MCP Server\nEncryption: Active\nTransport: STDIO`,
            mimeType: "text/plain"
          }]
        };
      }
    );
    
    // Set up request handlers
    await server.setToolRequestHandlers();
    await server.setResourceRequestHandlers();
    console.error("Request handlers configured");
    
    // Connect with JACS encryption
    await server.connect(secureTransport);
    console.error("JACS STDIO MCP Server running with encryption enabled");
    
  } catch (error) {
    console.error("Server error:", error);
    process.exit(1);
  }
}

main();