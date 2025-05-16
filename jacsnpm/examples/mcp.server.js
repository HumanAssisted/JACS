import { JacsMcpServer } from '../mcp.js';
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as http from 'node:http'; // Import Node.js's built-in HTTP module
import jacs from '../index.js'; // Assuming jacs NAPI is in index.js relative to mcp.js
                               // Adjust path if mcp.server.js is elsewhere.
                               // This requires jacs to be initialized/loaded.

// Create HTTP transport
// The port option here might be used by the transport for its own configuration,
// but the actual listening will be handled by the http.createServer below.
const transport = new StreamableHTTPServerTransport({
    // sessionIdGenerator can be added here if session management is needed,
    // similar to SDK examples. For a basic server, it might not be strictly necessary
    // depending on client/server interaction complexity.
});

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

async function main() {
    try {
        // 1. Load JACS config for the 'jacs' NAPI instance imported in this file.
        // This is crucial so that jacs.verifyResponse uses the server's identity/keys.
        console.log(`JACS Server (mcp.server.js): Pre-loading JACS config for server from: ${serverConfigPath}`);
        await jacs.load(serverConfigPath); 
        console.log("JACS Server (mcp.server.js): JACS config pre-loaded successfully for the 'jacs' import.");

        // 2. Connect the JacsMcpServer. 
        // Its internal call to this.loadJacsAgent() will also load the same config for its 'this.jacsAgent'.
        await server.connect(); 
        console.log("JACS Server (mcp.server.js): JacsMcpServer.connect() completed successfully.");
        
        // Sanity check that JacsMcpServer also has its agent reference
        if (!server.jacsAgent) { 
            console.error("JACS Server (mcp.server.js): CRITICAL - server.jacsAgent (in JacsMcpServer instance) is null after server.connect(). This indicates an issue in JacsMcpServer's connect/loadJacsAgent logic.");
            process.exit(1); // Critical failure
        }
    } catch (e) {
        console.error("JACS Server (mcp.server.js): CRITICAL - Error during initial JACS load or server.connect():", e);
        process.exit(1); // Abort if essential setup fails
    }

    // Create a Node.js HTTP server
    const httpServer = http.createServer(async (req, res) => {
        if (req.url === '/mcp' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                let parsedBody; // To ensure it's in scope for catch block's ID usage
                try {
                    parsedBody = JSON.parse(body);
                    console.log("JACS Server (mcp.server.js): Raw parsedBody from HTTP POST:", JSON.stringify(parsedBody, null, 2));

                    // *** JACS Pre-processing Hook for request.params ***
                    if (parsedBody.params && typeof parsedBody.params === 'string') {
                        console.log("JACS Server (mcp.server.js): 'params' is a string. Verifying JACS Document using jacs.verifyResponse.");
                        try {
                            const verifiedParamsObject = await jacs.verifyResponse(parsedBody.params); 
                            
                            console.log("JACS Server (mcp.server.js): Object from jacs.verifyResponse (expected original params):", JSON.stringify(verifiedParamsObject, null, 2));
                            
                            if (verifiedParamsObject && typeof verifiedParamsObject === 'object') {
                                parsedBody.params = verifiedParamsObject;
                                console.log("JACS Server (mcp.server.js): SUCCESS - 'params' is now the verified object:", JSON.stringify(parsedBody.params, null, 2));
                            } else {
                                console.error("JACS Server (mcp.server.js): ERROR - jacs.verifyResponse did not return a valid object for 'params'. Received:", verifiedParamsObject);
                                res.writeHead(400, { 'Content-Type': 'application/json' }); // Changed to application/json for consistency
                                res.end(JSON.stringify({ jsonrpc: "2.0", id: parsedBody.id || null, error: { code: -32004, message: "JACS params verification did not produce a valid object." } }));
                                return;
                            }
                        } catch (verificationError) {
                            console.error("JACS Server (mcp.server.js): CATCH ERROR - Verifying 'params' JACS Document failed:", verificationError);
                            let dataMessage = typeof verificationError === 'object' && verificationError !== null && verificationError.message ? verificationError.message : String(verificationError);
                            res.writeHead(400, { 'Content-Type': 'application/json' }); // Changed to application/json
                            res.end(JSON.stringify({ jsonrpc: "2.0", id: parsedBody.id || null, error: { code: -32001, message: "JACS signature verification failed for request params.", data: dataMessage } }));
                            return;
                        }
                    }
                    // *** End of JACS Pre-processing Hook ***

                    console.log("JACS Server (mcp.server.js): Forwarding to transport.handleRequest with processed body:", JSON.stringify(parsedBody, null, 2));
                    await transport.handleRequest(req, res, parsedBody);
                } catch (e) {
                    console.error("JACS Server (mcp.server.js): Error parsing JSON or other processing error in POST /mcp:", e);
                    res.writeHead(400, { 'Content-Type': 'application/json' }); // Changed to application/json
                    res.end(JSON.stringify({ jsonrpc: "2.0", id: (parsedBody ? parsedBody.id : null), error: {code: -32700, message: "Parse error or other processing error.", data: String(e.message)} }));
                }
            });
        } else if (req.url === '/mcp' && req.method === 'GET') {
            await transport.handleRequest(req, res);
        } else {
            res.writeHead(404); res.end();
        }
    });

    // Start the HTTP server and have it listen on port 3000
    const port = 3000;
    httpServer.listen(port, () => {
        console.log(`JACS MCP example server running on http://localhost:${port}/mcp`);
    });
}

main().catch(error => {
    console.error("JACS Server (mcp.server.js): Unhandled critical error in main setup:", error);
    process.exit(1);
});