#!/usr/bin/env node
/**
 * JACS MCP Server Example (Simplified API)
 *
 * A MCP server with JACS cryptographic signing using the simplified API.
 * This demonstrates how to create authenticated AI tool servers.
 *
 * Requirements:
 *   npm install @modelcontextprotocol/sdk zod
 *
 * Usage:
 *   # Start the server
 *   node mcp.simple.server.js
 *
 *   # Or with custom config
 *   JACS_CONFIG=./custom.config.json node mcp.simple.server.js
 *
 * The server provides these tools:
 *   - echo: Echo back a signed message
 *   - sign_data: Sign arbitrary data
 *   - verify_data: Verify signed data
 *   - agent_info: Get the server's agent information
 *   - export_agent: Get agent document for trust establishment
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from 'zod';
import * as jacs from '../simple.js';

const CONFIG_PATH = process.env.JACS_CONFIG || "./jacs.config.json";

async function main() {
  // All logs go to stderr (stdout is reserved for JSON-RPC)
  console.error("JACS Simple MCP Server starting...");

  try {
    // Load JACS agent using simplified API
    console.error(`Loading JACS agent from: ${CONFIG_PATH}`);
    const agentInfo = await jacs.load(CONFIG_PATH);
    console.error(`Agent loaded: ${agentInfo.agentId}`);

    // Verify agent integrity
    console.error("Verifying agent integrity...");
    const selfCheck = await jacs.verifySelf();
    if (!selfCheck.valid) {
      console.error(`Warning: Agent verification failed: ${selfCheck.errors.join(', ')}`);
    } else {
      console.error("Agent integrity verified.");
    }

    // Create MCP server
    const server = new McpServer({
      name: "jacs-simple-server",
      version: "1.0.0"
    });

    // Tool: Echo with signature
    server.tool(
      "echo",
      "Echo a message back with a cryptographic signature proving it came from this server.",
      { message: z.string().describe("The message to echo back") },
      async ({ message }) => {
        console.error(`[JACS] Tool 'echo' called with message="${message}"`);
        const signed = await jacs.signMessage({ echo: message });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              message,
              signed_by: signed.agentId,
              document_id: signed.documentId,
              timestamp: signed.timestamp,
              signed_document: signed.raw
            }, null, 2)
          }]
        };
      }
    );

    // Tool: Sign arbitrary data
    server.tool(
      "sign_data",
      "Sign arbitrary data and return the signed JACS document.",
      { data: z.string().describe("JSON string or text data to sign") },
      async ({ data }) => {
        console.error(`[JACS] Tool 'sign_data' called`);
        // Try to parse as JSON, otherwise sign as string
        let payload;
        try {
          payload = JSON.parse(data);
        } catch {
          payload = data;
        }
        const signed = await jacs.signMessage(payload);
        return {
          content: [{ type: "text", text: signed.raw }]
        };
      }
    );

    // Tool: Verify signed data
    server.tool(
      "verify_data",
      "Verify a signed JACS document and check its cryptographic signature.",
      { signed_document: z.string().describe("The signed JACS document JSON") },
      async ({ signed_document }) => {
        console.error(`[JACS] Tool 'verify_data' called`);
        const result = await jacs.verify(signed_document);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              valid: result.valid,
              signer_id: result.signerId,
              timestamp: result.timestamp,
              errors: result.errors
            }, null, 2)
          }]
        };
      }
    );

    // Tool: Get agent info
    server.tool(
      "agent_info",
      "Get information about this server's JACS agent for trust establishment.",
      {},
      async () => {
        console.error(`[JACS] Tool 'agent_info' called`);
        const info = jacs.getAgentInfo();
        if (!info) {
          return {
            content: [{ type: "text", text: JSON.stringify({ error: "No agent loaded" }) }]
          };
        }
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              agent_id: info.agentId,
              name: info.name,
              config_path: info.configPath,
              public_key_path: info.publicKeyPath
            }, null, 2)
          }]
        };
      }
    );

    // Tool: Export agent document
    server.tool(
      "export_agent",
      "Export the agent document for sharing with other parties for trust establishment.",
      {},
      async () => {
        console.error(`[JACS] Tool 'export_agent' called`);
        const agentDoc = jacs.exportAgent();
        return {
          content: [{ type: "text", text: agentDoc }]
        };
      }
    );

    // Tool: Get public key
    server.tool(
      "get_public_key",
      "Get this server's public key in PEM format for signature verification.",
      {},
      async () => {
        console.error(`[JACS] Tool 'get_public_key' called`);
        const pem = jacs.getPublicKey();
        return {
          content: [{ type: "text", text: pem }]
        };
      }
    );

    // Tool: Hash data
    server.tool(
      "hash",
      "Create a SHA-256 hash of the provided content.",
      { content: z.string().describe("The content to hash") },
      async ({ content }) => {
        console.error(`[JACS] Tool 'hash' called`);
        const hash = jacs.hashString(content);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ hash, algorithm: "SHA-256" }, null, 2)
          }]
        };
      }
    );

    // Resource: Agent document
    server.resource(
      "jacs-agent",
      "jacs://agent",
      async (uri) => {
        console.error(`[JACS] Resource 'jacs://agent' read`);
        return {
          contents: [{
            uri: uri.href,
            text: jacs.exportAgent(),
            mimeType: "application/json"
          }]
        };
      }
    );

    // Resource: Public key
    server.resource(
      "jacs-public-key",
      "jacs://public-key",
      async (uri) => {
        console.error(`[JACS] Resource 'jacs://public-key' read`);
        return {
          contents: [{
            uri: uri.href,
            text: jacs.getPublicKey(),
            mimeType: "application/x-pem-file"
          }]
        };
      }
    );

    // Connect via STDIO transport
    const transport = new StdioServerTransport();
    await server.connect(transport);

    console.error("\nJACS Simple MCP Server running.");
    console.error("Available tools:");
    console.error("  - echo: Echo back a signed message");
    console.error("  - sign_data: Sign arbitrary data");
    console.error("  - verify_data: Verify signed data");
    console.error("  - agent_info: Get agent information");
    console.error("  - export_agent: Get agent document");
    console.error("  - get_public_key: Get public key PEM");
    console.error("  - hash: Hash content with SHA-256");
    console.error("\nAvailable resources:");
    console.error("  - jacs://agent - Agent document");
    console.error("  - jacs://public-key - Public key");

  } catch (error) {
    console.error("Server error:", error);
    process.exit(1);
  }
}

main();
