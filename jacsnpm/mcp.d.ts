/// <reference types="node" />
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { IncomingMessage, ServerResponse } from "node:http";
export declare class TransportMiddleware implements Transport {
    private transport;
    private outgoingJacsTransformer?;
    private incomingJacsTransformer?;
    private jacsConfigPath?;
    private jacsOperational;
    private middlewareId;
    constructor(transport: Transport, role: "client" | "server", outgoingJacsTransformer?: ((msg: JSONRPCMessage) => Promise<string>) | undefined, incomingJacsTransformer?: ((payload: string) => Promise<JSONRPCMessage>) | undefined, jacsConfigPath?: string | undefined);
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: (message: JSONRPCMessage) => void;
    start(): Promise<void>;
    close(): Promise<void>;
    send(message: JSONRPCMessage): Promise<void>;
    get sessionId(): string | undefined;
    handlePostMessage(req: IncomingMessage & {
        auth?: any;
    }, res: ServerResponse, rawBodyString?: string): Promise<void>;
}
export declare function createJacsMiddleware(transport: Transport, configPath: string, role: "client" | "server"): TransportMiddleware;
export declare function createJacsMiddlewareAsync(transport: Transport, configPath: string, role: "client" | "server"): Promise<TransportMiddleware>;
