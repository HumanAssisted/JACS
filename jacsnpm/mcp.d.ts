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
    constructor(transport: Transport, outgoingJacsTransformer?: ((msg: JSONRPCMessage) => Promise<string>) | undefined, incomingJacsTransformer?: ((jacsInput: string | object, direction: 'incoming' | 'outgoing', messageType: 'request' | 'response' | 'notification' | 'error' | 'unknown') => Promise<JSONRPCMessage>) | undefined, jacsConfigPath?: string | undefined);
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
export declare function createJacsMiddleware(transport: Transport, configPath: string): TransportMiddleware;
export declare function createJacsMiddlewareAsync(transport: Transport, configPath: string): Promise<TransportMiddleware>;
/**
 *
 * great. I have what I need now in mcp.ts.
 Now I want to implement the actual  signatures.

Make sure the types are correct.
The middleware plugin uses this correctly
`import jacs from './index.js';`

The jacs should be loaded ONCE `  await jacs.load(options.configPath);` - once on load, not once per request.

This function is acltually verifying the incoming message , the request body from json rpc.
await jacs.verifyResponse(rawBody);  - so this will be inside verifyRequest


This function ` await jacs.signRequest(ctx.body);` actually signs the outgoing response. So this will be inside our mcp.ts signResponse.

THe are named this way because they are also used in a client, where those terms make more sense.

but SIGN on outgoing, VERIFY on incoming.

We MUST make sure the return types of our function and the verify function are correct.  In our functions, we can see the typescript types for the jacs plugin are strings and objects in both cases.

Critical question to answer first - how do we remove and inject our changes to the request and response schema? of the JSONRPCMessageSchema types?

request schema has method and params and we want to wrap the whole thing. Result schema seems pretty aribtrary, but that's fine aslong as we can wrap the result.

conceptually jacs is taking the json, changing it to a different json on sign, and on result restoring the original version. That means they could be strings or any type of object on result and strings strings and objects to represent json. Please ask if you need clarification

so
1. implement verifyRequest signResponse
2. make sure you understand how to wrap the key parts of jsonrpcMessage request and result


 */ 
