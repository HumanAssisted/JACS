import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { JacsAgent } from './index.js';
import { JacsClient } from './client.js';
/**
 * JACS Transport Proxy - Wraps any MCP transport with JACS signing/verification.
 *
 * Outgoing messages are signed with `signRequest()`.
 * Incoming messages are verified with `verifyResponse()`, falling back to
 * plain JSON if verification fails (the message was not JACS-signed).
 */
export declare class JACSTransportProxy implements Transport {
    private transport;
    private nativeAgent;
    private proxyId;
    private debug;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: (message: JSONRPCMessage) => void;
    constructor(transport: Transport, clientOrAgent: JacsClient | JacsAgent, role?: "client" | "server");
    start(): Promise<void>;
    close(): Promise<void>;
    send(message: JSONRPCMessage): Promise<void>;
    get sessionId(): string | undefined;
    private handleIncoming;
    /**
     * Removes null and undefined values from JSON objects to prevent MCP schema
     * validation failures with strict validators.
     *
     * Workaround for:
     * - https://github.com/modelcontextprotocol/typescript-sdk/issues/400
     * - https://github.com/anthropics/claude-code/issues/586
     * - https://github.com/agno-agi/agno/issues/2791
     */
    removeNullValues(obj: any): any;
}
/**
 * Create a transport proxy from a pre-loaded JacsClient or JacsAgent.
 */
export declare function createJACSTransportProxy(transport: Transport, clientOrAgent: JacsClient | JacsAgent, role?: "client" | "server"): JACSTransportProxy;
/**
 * Create a transport proxy by loading a JACS agent from a config file.
 * Awaits agent loading before returning, so the proxy is immediately usable.
 */
export declare function createJACSTransportProxyAsync(transport: Transport, configPath: string, role?: "client" | "server"): Promise<JACSTransportProxy>;
/** MCP tool definition shape (matches @modelcontextprotocol/sdk Tool type). */
export interface JacsMcpToolDef {
    name: string;
    description: string;
    inputSchema: {
        type: 'object';
        properties: Record<string, any>;
        required?: string[];
    };
}
/**
 * Returns the full list of JACS MCP tool definitions.
 *
 * Use this with `server.setRequestHandler(ListToolsRequestSchema, ...)` to
 * advertise JACS tools from a Node.js MCP server.
 */
export declare function getJacsMcpToolDefinitions(): JacsMcpToolDef[];
/**
 * Handle a JACS MCP tool call. Returns a JSON string result.
 *
 * Use this with `server.setRequestHandler(CallToolRequestSchema, ...)`.
 */
export declare function handleJacsMcpToolCall(client: JacsClient, toolName: string, args: Record<string, any>): Promise<{
    content: Array<{
        type: 'text';
        text: string;
    }>;
}>;
/**
 * Register all JACS tools on an MCP Server instance.
 *
 * Call this once during server setup to add JACS signing, verification,
 * agreements, trust, audit, and HAI integration tools.
 *
 * @example
 * ```typescript
 * import { Server } from '@modelcontextprotocol/sdk/server/index.js';
 * import { JacsClient } from '@hai.ai/jacs/client';
 * import { registerJacsTools } from '@hai.ai/jacs/mcp';
 *
 * const server = new Server(
 *   { name: 'my-server', version: '1.0.0' },
 *   { capabilities: { tools: {} } },
 * );
 * const client = await JacsClient.quickstart();
 * registerJacsTools(server, client);
 * ```
 */
export declare function registerJacsTools(server: any, client: JacsClient): void;
