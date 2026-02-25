import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { JacsAgent } from './index.js';
import { JacsClient } from './client.js';
/**
 * JACS Transport Proxy - Wraps any MCP transport with JACS signing/verification.
 *
 * Outgoing messages are signed with `signRequest()`.
 * Incoming messages are verified with `verifyResponse()`.
 *
 * Security defaults:
 * - local-only transport enforcement (`stdio` or loopback URL)
 * - fail-closed on signing/verification errors
 *
 * Local-only mode is mandatory and cannot be disabled.
 *
 * Optional fallback behavior:
 * - `allowUnsignedFallback: true` (or `JACS_MCP_ALLOW_UNSIGNED_FALLBACK=true`)
 */
export declare class JACSTransportProxy implements Transport {
    private transport;
    private nativeAgent;
    private proxyId;
    private debug;
    private allowUnsignedFallback;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: (message: JSONRPCMessage) => void;
    /**
     * Local/security policy options for MCP transport proxy behavior.
     */
    static readonly DEFAULT_LOCAL_ONLY = true;
    constructor(transport: Transport, clientOrAgent: JacsClient | JacsAgent, role?: "client" | "server", options?: JACSTransportProxyOptions);
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
export interface JACSTransportProxyOptions {
    /**
     * Reserved for compatibility. Local-only mode is always enforced.
     * Passing false throws an error.
     */
    localOnly?: boolean;
    /**
     * Allow fallback to unsigned/plain MCP messages when JACS signing or
     * verification fails. Default: false (fail closed).
     */
    allowUnsignedFallback?: boolean;
}
/**
 * Create a transport proxy from a pre-loaded JacsClient or JacsAgent.
 */
export declare function createJACSTransportProxy(transport: Transport, clientOrAgent: JacsClient | JacsAgent, role?: "client" | "server", options?: JACSTransportProxyOptions): JACSTransportProxy;
/**
 * Create a transport proxy by loading a JACS agent from a config file.
 * Awaits agent loading before returning, so the proxy is immediately usable.
 */
export declare function createJACSTransportProxyAsync(transport: Transport, configPath: string, role?: "client" | "server", options?: JACSTransportProxyOptions): Promise<JACSTransportProxy>;
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
 * agreements, trust, audit, and registry integration tools.
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
