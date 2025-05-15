import { JacsMcpServer } from '../mcp.js';
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as http from 'node:http'; // Import Node.js's built-in HTTP module

// Create HTTP transport
// The port option here might be used by the transport for its own configuration,
// but the actual listening will be handled by the http.createServer below.
const transport = new StreamableHTTPServerTransport({
    // sessionIdGenerator can be added here if session management is needed,
    // similar to SDK examples. For a basic server, it might not be strictly necessary
    // depending on client/server interaction complexity.
});

// Create server with custom transport and config
const server = new JacsMcpServer({
    name: "example-server",
    version: "1.0.0",
    transport: transport,
    configPath: "./jacs.server.config.json"  
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

async function main() {
    // Connect the JacsMcpServer to the transport.
    // This prepares the server to handle MCP messages via the transport.
    await server.connect();

    // Create a Node.js HTTP server
    const httpServer = http.createServer(async (req, res) => {
        if (req.url === '/mcp') { // MCP requests are typically routed to a specific path
            if (req.method === 'POST') {
                let body = '';
                req.on('data', chunk => {
                    body += chunk.toString();
                });
                req.on('end', async () => {
                    try {
                        const parsedBody = JSON.parse(body);
                        await transport.handleRequest(req, res, parsedBody);
                    } catch (e) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Invalid JSON body' }));
                    }
                });
            } else if (req.method === 'GET') {
                // GET requests to /mcp are often used for Server-Sent Events (SSE) channels
                await transport.handleRequest(req, res);
            } else {
                res.writeHead(405); // Method Not Allowed
                res.end();
            }
        } else {
            res.writeHead(404); // Not Found
            res.end();
        }
    });

    // Start the HTTP server and have it listen on port 3000
    const port = 3000;
    httpServer.listen(port, () => {
        console.log(`JACS MCP example server running on http://localhost:${port}/mcp`);
    });
}

main().catch(console.error);