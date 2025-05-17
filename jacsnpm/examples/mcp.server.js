import { JacsMcpServer } from '../mcp.js';
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
// import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as http from 'node:http'; // Import Node.js's built-in HTTP module
import jacs from '../index.js'; // Assuming jacs NAPI is in index.js relative to mcp.js
                               // Adjust path if mcp.server.js is elsewhere.
                               // This requires jacs to be initialized/loaded.

// Create HTTP transport
// The port option here might be used by the transport for its own configuration,
// but the actual listening will be handled by the http.createServer below.
// const transport = new StreamableHTTPServerTransport({
//     // sessionIdGenerator can be added here if session management is needed,
//     // similar to SDK examples. For a basic server, it might not be strictly necessary
//     // depending on client/server interaction complexity.
// });
const transport = new StdioServerTransport();
// Create server with custom transport and config
const serverConfigPath = "./jacs.server.config.json"; // Used for both jacs.load here and JacsMcpServer
const server = new JacsMcpServer({
    name: "example-server",
    version: "1.0.0",
    transport: transport,
    configPath: serverConfigPath  
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


await server.connect();
