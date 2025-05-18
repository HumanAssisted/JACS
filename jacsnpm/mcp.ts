// middleware.ts
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage, isJSONRPCRequest, isJSONRPCResponse, isJSONRPCNotification } from "@modelcontextprotocol/sdk/types.js";

export type RequestTransformer = (message: JSONRPCMessage) => JSONRPCMessage | Promise<JSONRPCMessage>;
export type ResponseTransformer = (message: JSONRPCMessage) => JSONRPCMessage | Promise<JSONRPCMessage>;

export class TransportMiddleware implements Transport {
  constructor(
    private transport: Transport,
    private requestTransformer?: RequestTransformer,
    private responseTransformer?: ResponseTransformer
  ) {
    // Setup message handler to intercept responses
    this.transport.onmessage = async (message) => {
      if (this.responseTransformer && (isJSONRPCResponse(message) || isJSONRPCRequest(message))) {
        message = await this.responseTransformer(message);
      }
      this.onmessage?.(message);
    };
    
    // Forward other handlers
    this.transport.onclose = () => this.onclose?.();
    this.transport.onerror = (error) => this.onerror?.(error);
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
    if (this.requestTransformer) {
      message = await this.requestTransformer(message);
    }
    return this.transport.send(message);
  }

  // Forward session ID if available
  get sessionId(): string | undefined {
    return (this.transport as any).sessionId;
  }
}

// Example verification functions
export function verifyRequest(message: JSONRPCMessage): JSONRPCMessage {
  console.log(`Verifying request: ${isJSONRPCRequest(message) || isJSONRPCNotification(message) ? message.method : 'response'}`);
  return message;
}

export function signResponse(message: JSONRPCMessage): JSONRPCMessage {
  console.log(`Signing response: ${(message as any).id || 'notification'}`);
  return message;
}