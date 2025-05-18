import { JacsMcpClient } from '../mcp.js';
import path from 'path'; // Import the path module
import { fileURLToPath } from 'url'; // To get __dirname in ES modules

// Get current directory for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// StdioClientTransport is not used if connecting via HTTP, so it can be removed if not needed for other purposes.
// import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"; 

// Define the password. In a real application, you might get this
// from a more secure source or an environment variable in the client's own process.
const JACS_SERVER_PRIVATE_KEY_PASSWORD = "hello"; // Ensure this is correct

// Create a JACS-enabled MCP client for Stdio
const client = new JacsMcpClient({
    name: "example-client",
    version: "1.0.0",
    command: "node", // Command to execute the server
    args: ["mcp.server.js"], // Path to the server script, relative to client's CWD
                            // If running client from 'examples' dir, this is correct.
    configPath: "./jacs.client.config.json", // Path to JACS client config
    stdioEnv: {
        ...process.env, // Inherit all environment variables from the parent (client) process
        "JACS_PRIVATE_KEY_PASSWORD": JACS_SERVER_PRIVATE_KEY_PASSWORD // Add/override specific variables
    },
    stdioCwd: __dirname // Set CWD to the directory of mcp.client.js (i.e., examples/)
                       // This ensures mcp.server.js finds ./jacs.server.config.json
});

// Example usage
async function runExample() {
    try {
        // Explicitly connect the client. This will spawn the server process.
        console.log('Attempting to connect client and spawn server...');
        await client.connect();
        console.log('Client connected to server via Stdio.');

        // List tools (as an example, since server has an "add" tool)
        const tools = await client.listTools();
        console.log('Available tools:', tools);
        
        if (tools.tools.find(t => t.name === 'add')) {
            // Call the "add" tool
            const addResult = await client.callTool({
                name: "add",
                arguments: {
                    a: 5,
                    b: 3
                }
            });
            console.log('Addition result (5+3):', addResult);
        } else {
            console.log('Tool "add" not found.');
        }

        if (tools.tools.find(t => t.name === 'greeting')) { // Assuming greeting is a tool, if it is a resource, this call will fail
             // Call the "greeting" resource (if it were a tool)
             // Note: The server registers "greeting" as a resource, not a tool.
             // To interact with it, you'd use listResources and readResource.
        }

        // List resources
        const resources = await client.listResources();
        console.log('Available resources:', resources);

        // Try to read the "greeting" resource if available
        // The greeting resource is templated: "greeting://{name}"
        const greetingResourceUri = "greeting://world"; // Example URI
        try {
            const greetingResource = await client.readResource({
                uri: greetingResourceUri
            });
            console.log(`Resource content for '${greetingResourceUri}':`, greetingResource);
        } catch (e) {
            console.error(`Error reading resource '${greetingResourceUri}': ${e.message}`);
        }


        // The original example calls for prompts and other resources not defined in the Stdio server snippet.
        // You can add them to your mcp.server.js if needed.
        // For example:
        // List prompts
        // const prompts = await client.listPrompts();
        // console.log('Available prompts:', prompts);

        // Read a generic resource (will likely fail unless "file:///example.txt" is specifically served)
        // try {
        //     const genericResource = await client.readResource({
        //         uri: "file:///example.txt"
        //     });
        //     console.log('Generic resource content:', genericResource);
        // } catch (e) {
        //     console.error("Error reading 'file:///example.txt':", e.message);
        // }


    } catch (error) {
        console.error('Client runExample Error:', error);
    } finally {
        // Close the client connection if possible.
        // For StdioClientTransport, this should terminate the child process.
        if (client.isConnected()) {
            console.log("Closing client connection...");
            await client.close();
            console.log("Client connection closed.");
        }
    }
}

// Run the example
runExample();