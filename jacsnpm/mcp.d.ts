import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { IncomingMessage, ServerResponse } from "node:http";
/**
 * JACS Transport Proxy - Wraps any transport with JACS encryption
 *
 * This proxy sits between the MCP SDK and the actual transport,
 * intercepting serialized JSON strings (not JSON-RPC objects)
 */
export declare class JACSTransportProxy implements Transport {
    private transport;
    private jacsConfigPath?;
    private jacsOperational;
    private proxyId;
    constructor(transport: Transport, role: "client" | "server", jacsConfigPath?: string | undefined);
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: (message: JSONRPCMessage) => void;
    start(): Promise<void>;
    close(): Promise<void>;
    send(message: JSONRPCMessage): Promise<void>;
    get sessionId(): string | undefined;
    /**
     * REQUIRED for SSE (Server-Sent Events) transport pattern in MCP.
     *
     * WHY THIS EXISTS:
     * SSE is inherently unidirectional (server→client), but MCP requires bidirectional communication.
     * The MCP SSE implementation solves this with a hybrid approach:
     * - Server→Client: Uses SSE stream for real-time messages
     * - Client→Server: Uses HTTP POST to a specific endpoint
     *
     * This function intercepts those client POST requests, decrypts JACS payloads,
     * and forwards the decrypted messages to the underlying SSE transport handler.
     *
     * Without this, JACS-encrypted client messages would never reach the MCP server.
     */
    handlePostMessage?(req: IncomingMessage & {
        auth?: any;
    }, res: ServerResponse, rawBodyString?: string): Promise<void>;
    private handleIncomingMessage;
    /**
     * Removes null and undefined values from JSON objects to prevent MCP schema validation failures.
     *
     * WORKAROUND for MCP JSON Schema validation issues:
     * - Addresses strict validators (like Anthropic's API) that reject schemas with null values
     * - Handles edge cases where tools have null inputSchema causing client validation errors
     * - Prevents "invalid_type: expected object, received undefined" errors in TypeScript SDK v1.9.0
     * - Cleans up malformed schemas before transmission to avoid -32602 JSON-RPC errors
     *
     * Related issues:
     * - https://github.com/modelcontextprotocol/typescript-sdk/issues/400 (null schema tools)
     * - https://github.com/anthropics/claude-code/issues/586 (Anthropic strict Draft 2020-12)
     * - https://github.com/agno-agi/agno/issues/2791 (missing type field)
     *
     * @param obj - The object to clean (typically MCP tool/resource schemas)
     * @returns A new object with all null/undefined values recursively removed
     */
    private removeNullValues;
}
export declare function createJACSTransportProxy(transport: Transport, configPath: string, role: "client" | "server"): JACSTransportProxy;
export declare function createJACSTransportProxyAsync(transport: Transport, configPath: string, role: "client" | "server"): Promise<JACSTransportProxy>;
