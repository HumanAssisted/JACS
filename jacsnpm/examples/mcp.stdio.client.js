#!/usr/bin/env node
/**
 * MCP Client with JACS encryption using STDIO transport
 * This client spawns and communicates with a JACS-encrypted STDIO server
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createJACSTransportProxy } from '../mcp.js';
import { fileURLToPath } from 'url';
import path from 'path';

const CLIENT_CONFIG_PATH = "./jacs.client.config.json";

// Get the server script path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const serverPath = path.join(__dirname, 'mcp.stdio.server.js');

async function main() {
  console.log("JACS STDIO MCP Client starting...");
  
  let client = null;
  
  try {
    // Create STDIO transport that spawns our JACS server
    const baseTransport = new StdioClientTransport({
      command: "node",
      args: [serverPath],
      env: {
        ...process.env,
        JACS_PRIVATE_KEY_PASSWORD: "hello" // Pass password to server
      }
    });
    console.log("StdioClientTransport created, spawning server...");
    
    // Wrap with JACS encryption  
    const secureTransport = createJACSTransportProxy(
      baseTransport,
      CLIENT_CONFIG_PATH,
      "client"
    );
    console.log("JACS transport proxy created");
    
    // Create client
    client = new Client({
      name: "jacs-stdio-client", 
      version: "1.0.0"
    });
    
    // Connect with JACS encryption
    await client.connect(secureTransport);
    console.log("✅ Connected to JACS-encrypted STDIO server!");
    
    // Test tools
    console.log("\n📋 Listing available tools...");
    const tools = await client.listTools();
    console.log("Available tools:", tools.tools.map(t => t.name));
    
    // Test add tool
    if (tools.tools.find(t => t.name === 'add')) {
      console.log("\n🧮 Testing add tool...");
      const addResult = await client.callTool({
        name: "add",
        arguments: { a: 25, b: 17 }
      });
      console.log("Addition result (25+17):", addResult.content[0].text);
    }
    
    // Test echo tool  
    if (tools.tools.find(t => t.name === 'echo')) {
      console.log("\n📢 Testing echo tool...");
      const echoResult = await client.callTool({
        name: "echo", 
        arguments: { message: "Hello JACS STDIO!" }
      });
      console.log("Echo result:", echoResult.content[0].text);
    }
    
    // Test resources
    console.log("\n📄 Listing available resources...");
    const resources = await client.listResources();
    console.log("Available resources:", resources.resources.map(r => r.name));
    
    // Read server info resource
    if (resources.resources.find(r => r.uri === 'info://server')) {
      console.log("\n📖 Reading server-info resource...");
      const serverInfo = await client.readResource({
        uri: "info://server"
      });
      console.log("Server info:", serverInfo.contents[0].text);
    }
    
    console.log("\n✅ All JACS STDIO tests completed successfully!");
    
  } catch (error) {
    console.error("❌ Client error:", error);
    process.exit(1);
  } finally {
    if (client) {
      console.log("\n🔌 Closing connection...");
      await client.close();
      console.log("Connection closed.");
    }
  }
}

main(); 