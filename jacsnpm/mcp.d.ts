/// <reference types="node" />
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
    handlePostMessage?(req: IncomingMessage & {
        auth?: any;
    }, res: ServerResponse, rawBodyString?: string): Promise<void>;
    private handleIncomingMessage;
    private removeNullValues;
}
export declare function createJACSTransportProxy(transport: Transport, configPath: string, role: "client" | "server"): JACSTransportProxy;
export declare function createJACSTransportProxyAsync(transport: Transport, configPath: string, role: "client" | "server"): Promise<JACSTransportProxy>;
