// middleware.ts
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage, isJSONRPCRequest, isJSONRPCResponse, isJSONRPCNotification } from "@modelcontextprotocol/sdk/types.js";
import jacs from './index.js';
import { IncomingMessage, ServerResponse } from "node:http";

// Load JACS config only once
let jacsLoaded = false;
async function ensureJacsLoaded(configPath: string) {
  if (!jacsLoaded) {
    await jacs.load(configPath);
    jacsLoaded = true;
  }
}

export type RequestTransformer = (message: JSONRPCMessage) => JSONRPCMessage | Promise<JSONRPCMessage>;
export type ResponseTransformer = (message: JSONRPCMessage) => 
  JSONRPCMessage | string | Promise<JSONRPCMessage | string>;

export class TransportMiddleware implements Transport {
  constructor(
    private transport: Transport,
    private requestTransformer?: RequestTransformer,
    private responseTransformer?: ResponseTransformer,
    private jacsConfigPath?: string
  ) {
    // Setup message handler to intercept responses
    this.transport.onmessage = async (message) => {
      console.log(`Middleware received message type: ${typeof message}`);
      
      try {
        // If we received a JACS string, verify it first
        if (typeof message === 'string') {
          console.log("Received string message, verifying JACS");
          const verifiedMessage = await jacs.verifyResponse(message);
          console.log(`Verified to: ${typeof verifiedMessage}, passing to handler`);
          this.onmessage?.(verifiedMessage as JSONRPCMessage);
          return;
        }
        
        // Otherwise apply transformer if needed
        if (this.responseTransformer && (isJSONRPCResponse(message) || isJSONRPCRequest(message))) {
          const transformedMessage = await this.responseTransformer(message);
          if (typeof transformedMessage === 'string') {
            console.log("Transformer returned string, verifying JACS");
            const verifiedMessage = await jacs.verifyResponse(transformedMessage);
            console.log(`Verified message: ${typeof verifiedMessage} ${verifiedMessage}`);
            this.onmessage?.(verifiedMessage as JSONRPCMessage);
            return; // Skip further processing
          }
          message = transformedMessage as JSONRPCMessage;
        }
        
        this.onmessage?.(message);
      } catch (error) {
        console.error("Error in middleware onmessage:", error);
        this.onerror?.(error as Error);
      }
    };
    
    // Forward other handlers
    this.transport.onclose = () => this.onclose?.();
    this.transport.onerror = (error) => this.onerror?.(error);
    
    // Initialize JACS if config path is provided
    if (jacsConfigPath) {
      ensureJacsLoaded(jacsConfigPath).catch(err => {
        console.error("Failed to load JACS configuration:", err);
      });
    }
  }

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  async start(): Promise<void> {
    return this.transport.start();
  }

  async close(): Promise<void> {
    return this.transport.close();
  }

  async send(message: JSONRPCMessage): Promise<void> {
    console.log(`Middleware sending message type: ${typeof message}`);
    if (this.requestTransformer) {
      message = await this.requestTransformer(message);
      console.log(`After transformer, message type: ${typeof message}`);
    }
    return this.transport.send(message);
  }

  // Forward session ID if available
  get sessionId(): string | undefined {
    return (this.transport as any).sessionId;
  }

  handlePostMessage(req: IncomingMessage & { auth?: any }, res: ServerResponse, parsedBody?: unknown): Promise<void> {
    if (this.transport && 
        typeof this.transport === 'object' && 
        'handlePostMessage' in this.transport && 
        typeof (this.transport as any).handlePostMessage === 'function') {
      return (this.transport as any).handlePostMessage(req, res, parsedBody);
    }
    throw new Error("Underlying transport doesn't support handlePostMessage");
  }
}

// Verify incoming request - processes JACS-signed strings back to JSON-RPC messages
export async function verifyRequest(message: JSONRPCMessage): Promise<JSONRPCMessage> {
  console.log(`Verifying request: ${isJSONRPCRequest(message) || isJSONRPCNotification(message) ? message.method : 'response'}`);
  return message; // Don't transform requests - let the middleware do it directly in onmessage
}

// Sign outgoing response - converts JSON-RPC messages to JACS-signed strings
export async function signResponse(message: JSONRPCMessage): Promise<JSONRPCMessage | string> {
  console.log(`Signing response: ${typeof message === 'object' ? JSON.stringify(message).substring(0, 100) + '...' : message}`);
  
  try {
    // Only sign responses and objects
    if ((isJSONRPCResponse(message) || isJSONRPCRequest(message)) && typeof message === 'object') {
      const signedMessage = await jacs.signRequest(message);
      console.log(`Signed message type: ${typeof signedMessage}, length: ${typeof signedMessage === 'string' ? signedMessage.length : 'N/A'}`);
      // Return as string - this is correct
      return signedMessage as string;
    }
  } catch (error) {
    console.error("JACS signing failed:", error);
  }
  
  return message;
}

// Helper function to create middleware with JACS integration
export function createJacsMiddleware(
  transport: Transport, 
  configPath: string
): TransportMiddleware {
  return new TransportMiddleware(
    transport,
    verifyRequest,
    signResponse,
    configPath
  );
}

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