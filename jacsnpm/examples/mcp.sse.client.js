import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { createJACSTransportProxy } from '../mcp.js';
// No longer need path or fileURLToPath for stdio server spawning

const SERVER_URL = "http://localhost:3000/sse"; // Matches the server's SSE path
const CLIENT_CONFIG_PATH = "./jacs.client.config.json";

async function runExample() {
    let client = null;
    
    try {
        console.log(`Connecting to SSE server at ${SERVER_URL} with JACS middleware...`);

        const baseTransport  = new SSEClientTransport(new URL(SERVER_URL));
        console.log('1!');
        const secureTransport = createJACSTransportProxy(
            baseTransport,
            CLIENT_CONFIG_PATH,
            "client"
        );      
        
        console.log('2!'); 
        client = new Client({
            name: "example-sse-client",
            version: "1.0.0"
        });

        console.log('3!'); 
        await client.connect(secureTransport);
        console.log('Client connected successfully!');

        // List tools
        console.log('Requesting tools list...');
        const tools = await client.listTools();
        console.log('Available tools:', tools);
        
        if (tools.tools.find(t => t.name === 'add')) {
            console.log('Calling add tool...');
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
        console.log('Requesting resources list...');
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
        console.error('Client error:', error);
    } finally {
        if (client && client.transport) {
            console.log("Closing client connection...");
            await client.close();
            console.log("Client connection closed.");
        }
    }
}

runExample();