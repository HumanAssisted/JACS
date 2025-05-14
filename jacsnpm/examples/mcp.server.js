import { JacsMcpServer } from '../mcp.js';
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Create a JACS-enabled MCP server
const server = new JacsMcpServer({
  name: "Demo",
  version: "1.0.0",
  configPath: "./config.json"  // JACS config path
});

// Add an addition tool
server.tool("add",
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({
    content: [{ type: "text", text: String(a + b) }]
  })
);

// Add a dynamic greeting resource
server.resource(
  "greeting",
  new ResourceTemplate("greeting://{name}", { list: undefined }),
  async (uri, { name }) => ({
    contents: [{
      uri: uri.href,
      text: `Hello, ${name}!`
    }]
  })
);

// Add a JACS document tool example
server.tool("processDocument",
  { document: z.string() },
  async ({ document }) => ({
    content: [{ 
      type: "text", 
      text: "Document processed",
      document: document  // Will be automatically signed by JACS middleware
    }]
  })
);

// Start receiving messages on stdin and sending messages on stdout
const transport = new StdioServerTransport();
await server.connect(transport);