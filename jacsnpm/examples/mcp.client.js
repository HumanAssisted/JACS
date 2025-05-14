import { JacsMcpClient } from '../mcp.js';
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// Create a JACS-enabled MCP client
const client = new JacsMcpClient({
    name: "example-client",
    version: "1.0.0",
    url: "http://localhost:3000/mcp",  // For HTTP transport
    configPath: "./config.json"        // JACS config path
});

// Example usage
async function runExample() {
    try {
        // List prompts
        const prompts = await client.listPrompts();
        console.log('Available prompts:', prompts);

        // Get a prompt
        const prompt = await client.getPrompt({
            name: "example-prompt",
            arguments: {
                arg1: "value"
            }
        });
        console.log('Prompt result:', prompt);

        // List resources
        const resources = await client.listResources();
        console.log('Available resources:', resources);

        // Read a resource
        const resource = await client.readResource({
            uri: "file:///example.txt"
        });
        console.log('Resource content:', resource);

        // Call a regular tool
        const addResult = await client.callTool({
            name: "add",
            arguments: {
                a: 5,
                b: 3
            }
        });
        console.log('Addition result:', addResult);

        // Call a tool with a document (will be automatically signed)
        const docResult = await client.callTool({
            name: "processDocument",
            arguments: {
                document: JSON.stringify({
                    content: "Hello, World!",
                    timestamp: new Date().toISOString()
                })
            }
        });
        console.log('Document processing result:', docResult);

    } catch (error) {
        console.error('Error:', error);
    }
}

// Run the example
runExample();