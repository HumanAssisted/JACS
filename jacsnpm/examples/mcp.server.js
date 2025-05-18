console.log(`SPAWNED_SERVER_LOG: Original mcp.server.js starting. CWD: ${process.cwd()}. Timestamp: ${new Date().toISOString()}`);
console.error(`SPAWNED_SERVER_ERROR_LOG: Original mcp.server.js starting. Timestamp: ${new Date().toISOString()}`);

import { JacsMcpServer } from '../mcp.js';
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
// import * as http from 'node:http'; // Not used for Stdio
// import jacs from '../index.js'; // JacsMcpServer handles its own jacs instance loading via configPath

const transport = new StdioServerTransport();
const serverConfigPath = "./jacs.server.config.json"; 
const server = new JacsMcpServer({
    name: "example-server",
    version: "1.0.0",
    transport: transport,
    configPath: serverConfigPath  
});

server.tool("add",
    { a: z.number(), b: z.number() },
    async ({ a, b }) => ({
        content: [{ type: "text", text: String(a + b) }]
    })
);

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
    console.error("SPAWNED_SERVER_ERROR_LOG: Attempting server.connect()...");
    await server.connect();
    console.error("SPAWNED_SERVER_ERROR_LOG: server.connect() successful. Server should be listening on stdio.");
    // For Stdio transport, there's no explicit "listening" log like with HTTP,
    // it's just ready to process messages on stdin/stdout.
    // Keep the process alive. For Stdio, it just needs to not exit.
    // A real server would have a loop or be event-driven.
    // For this test, we'll just let it run. If the client disconnects, it might exit.
  } catch (err) {
    console.error("SPAWNED_SERVER_ERROR_LOG: Error during server setup or connect:", err);
    process.exit(1); // Exit if server setup fails
  }
}

main();
