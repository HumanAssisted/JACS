import { JacsMcpClient } from '../mcp.js';
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
// No longer need path or fileURLToPath for stdio server spawning

const SERVER_URL = "http://localhost:3000/sse"; // Matches the server's SSE path

// Create a JACS-enabled MCP client for SSE
const client = new JacsMcpClient({
    name: "example-sse-client",
    version: "1.0.0",
    // For SSE, we don't use command/args. The server must be running independently.
    // configPath is still needed for JACS client-side configuration.
    configPath: "./jacs.client.config.json",
    // stdioEnv and stdioCwd are not applicable to SSE transport
});

// Example usage
async function runExample() {
    try {
        const transport = new SSEClientTransport(new URL(SERVER_URL));
        console.log("[mcp.sse.client.js] Created SSEClientTransport instance. Type:", typeof transport, "Instance:", transport);
        if (transport) {
            console.log("[mcp.sse.client.js] SSEClientTransport has .send method:", typeof transport.send === 'function');
        }

        // Explicitly connect the client using the SSE transport.
        console.log(`Attempting to connect client to SSE server at ${SERVER_URL}...`);
        // The JacsMcpClient.connect method needs to accept a transport instance
        await client.connect(transport);
        console.log('Client connected to server via SSE.');

        // List tools
        const tools = await client.listTools();
        console.log('Available tools:', tools);
        
        if (tools.tools.find(t => t.name === 'add')) {
            // Call the "add" tool
            const addResult = await client.callTool({
                name: "add",
                arguments: {
                    a: 15,
                    b: 7
                }
            });
            console.log('Addition result (15+7):', addResult);
        } else {
            console.log('Tool "add" not found.');
        }

        // List resources
        const resources = await client.listResources();
        console.log('Available resources:', resources);

        // Try to read the "greeting" resource if available
        const greetingResourceUri = "greeting://SSE_User"; // Example URI
        try {
            const greetingResource = await client.readResource({
                uri: greetingResourceUri
            });
            console.log(`Resource content for '${greetingResourceUri}':`, greetingResource);
        } catch (e) {
            console.error(`Error reading resource '${greetingResourceUri}': ${e.message}`);
        }

    } catch (error) {
        console.error('Client runExample Error:', error);
    } finally {
        if (client.isConnected()) {
            console.log("Closing client connection...");
            await client.close();
            console.log("Client connection closed.");
        }
    }
}

runExample();