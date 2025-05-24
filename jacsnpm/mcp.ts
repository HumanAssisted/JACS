// Transport Proxy Pattern - Intercepts at network boundary, not message level
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import jacs from './index.js';
import { IncomingMessage, ServerResponse } from "node:http";

// Load JACS config only once
let jacsLoaded = false;
let jacsLoadError: Error | null = null;

async function ensureJacsLoaded(configPath: string): Promise<void> {
  if (jacsLoaded) return;
  if (jacsLoadError) throw jacsLoadError;

  try {
    console.log(`ensureJacsLoaded: Attempting to load JACS config from: ${configPath}`);
    jacsLoadError = null; 
    await jacs.load(configPath);
    jacsLoaded = true;
    console.log(`ensureJacsLoaded: JACS agent loaded successfully from ${configPath}.`);
  } catch (error) {
    jacsLoadError = error as Error;
    console.error(`ensureJacsLoaded: CRITICAL: Failed to load JACS config from '${configPath}'. Error:`, jacsLoadError.message); 
    throw jacsLoadError;
  }
}

const enableDiagnosticLogging = process.env.JACS_MCP_DEBUG === 'true';

/**
 * JACS Transport Proxy - Wraps any transport with JACS encryption
 * 
 * This proxy sits between the MCP SDK and the actual transport,
 * intercepting serialized JSON strings (not JSON-RPC objects)
 */
export class JACSTransportProxy implements Transport {
  private jacsOperational = true;
  private proxyId: string;

  constructor(
    private transport: Transport,
    role: "client" | "server",
    private jacsConfigPath?: string
  ) {
    this.proxyId = `JACS_${role.toUpperCase()}_PROXY`;
    console.log(`[${this.proxyId}] CONSTRUCTOR: Wrapping transport with JACS. Config: ${jacsConfigPath}`);

    if (jacsConfigPath) {
      ensureJacsLoaded(jacsConfigPath)
        .then(() => { 
          this.jacsOperational = true; 
          console.log(`[${this.proxyId}] JACS Loaded and operational.`); 
        })
        .catch(err => { 
          this.jacsOperational = false; 
          console.error(`[${this.proxyId}] JACS Load FAILED:`, err.message); 
        });
    } else {
      this.jacsOperational = false;
      console.warn(`[${this.proxyId}] No JACS config provided. Operating in passthrough mode.`);
    }

    // Intercept incoming messages from the transport
    this.transport.onmessage = async (incomingData: string | JSONRPCMessage | object) => {
      const logPrefix = `[${this.proxyId}] INCOMING`;
      
      try {
        let messageForSDK: JSONRPCMessage;

        if (typeof incomingData === 'string') {
          if (enableDiagnosticLogging) console.log(`${logPrefix}: Received string from transport (len ${incomingData.length}): ${incomingData.substring(0,100)}...`);
          
          if (this.jacsOperational) {
            // Try to decrypt/verify the string as a JACS artifact
            try {
              if (enableDiagnosticLogging) console.log(`${logPrefix}: Attempting JACS verification of string...`);
              const verificationResult = await jacs.verifyResponse(incomingData);
              
              let decryptedMessage: JSONRPCMessage;
              if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
                decryptedMessage = verificationResult.payload as JSONRPCMessage;
              } else {
                decryptedMessage = verificationResult as JSONRPCMessage;
              }
              
              if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS verification successful. Decrypted message: ${JSON.stringify(decryptedMessage).substring(0,100)}...`);
              messageForSDK = decryptedMessage;
            } catch (jacsError) {
              // Not a JACS artifact, treat as plain JSON
              const errorMessage = jacsError instanceof Error ? jacsError.message : "Unknown JACS error";
              if (enableDiagnosticLogging) console.log(`${logPrefix}: Not a JACS artifact, parsing as plain JSON. JACS error was: ${errorMessage}`);
              messageForSDK = JSON.parse(incomingData) as JSONRPCMessage;
            }
          } else {
            // JACS not operational, parse as plain JSON
            if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS not operational, parsing as plain JSON.`);
            messageForSDK = JSON.parse(incomingData) as JSONRPCMessage;
          }
        } else if (typeof incomingData === 'object' && incomingData !== null && 'jsonrpc' in incomingData) {
          if (enableDiagnosticLogging) console.log(`${logPrefix}: Received object from transport, using as-is.`);
          messageForSDK = incomingData as JSONRPCMessage;
        } else {
          console.error(`${logPrefix}: Unexpected data type from transport:`, typeof incomingData);
          throw new Error("Invalid data type from transport");
        }

        if (enableDiagnosticLogging) console.log(`${logPrefix}: Passing to MCP SDK: ${JSON.stringify(messageForSDK).substring(0,100)}...`);
        
        // Pass the clean JSON-RPC message to the MCP SDK
        if (this.onmessage) {
          this.onmessage(messageForSDK);
        }
      } catch (error) {
        console.error(`${logPrefix}: Error processing incoming message:`, error);
        if (this.onerror) this.onerror(error as Error);
      }
    };

    // Forward transport events
    this.transport.onclose = () => { 
      console.log(`[${this.proxyId}] Transport closed.`);
      if (this.onclose) this.onclose(); 
    };
    
    this.transport.onerror = (error) => { 
      console.error(`[${this.proxyId}] Transport error:`, error);
      if (this.onerror) this.onerror(error); 
    };

    console.log(`[${this.proxyId}] CONSTRUCTOR: Transport proxy initialized.`);

    if ('send' in this.transport && typeof this.transport.send === 'function') {
      const originalSend = this.transport.send.bind(this.transport);
      this.transport.send = async (data: any) => {
        if (typeof data === 'string') {
          // Handle raw JACS strings directly
          const sseTransport = this.transport as any;
          if (sseTransport._endpoint) {
            const headers = await (sseTransport._commonHeaders?.() || Promise.resolve({}));
            const response = await fetch(sseTransport._endpoint, {
              method: "POST",
              headers: {
                ...headers,
                "content-type": "application/json",
              },
              body: data, // Send raw string without JSON.stringify()
            });
            if (!response.ok) {
              const text = await response.text().catch(() => null);
              throw new Error(`Error POSTing to endpoint (HTTP ${response.status}): ${text}`);
            }
            return;
          }
        }
        // Fall back to original send for objects
        return originalSend(data);
      };
    }
  }

  // MCP SDK will set these
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  async start(): Promise<void> { 
    console.log(`[${this.proxyId}] Starting underlying transport...`);
    return this.transport.start(); 
  }
  
  async close(): Promise<void> { 
    console.log(`[${this.proxyId}] Closing underlying transport...`);
    return this.transport.close(); 
  }

  // Intercept outgoing messages to the transport
  async send(message: JSONRPCMessage): Promise<void> {
    const logPrefix = `[${this.proxyId}] OUTGOING`;
    
    try {
      if (enableDiagnosticLogging) console.log(`${logPrefix}: MCP SDK sending message: ${JSON.stringify(message).substring(0,100)}...`);

      if (this.jacsOperational) {
        // Skip JACS for error responses
        if ('error' in message) {
          if (enableDiagnosticLogging) console.log(`${logPrefix}: Error response, skipping JACS encryption.`);
          await this.transport.send(message);
        } else {
          try {
            if (enableDiagnosticLogging) console.log(`${logPrefix}: Applying JACS encryption to message...`);
            const jacsArtifact = await jacs.signRequest(message);
            
            const jacsObject = JSON.parse(jacsArtifact);
            await this.transport.send(jacsObject as any);
          } catch (jacsError) {
            console.error(`${logPrefix}: JACS encryption failed, sending plain message. Error:`, jacsError);
            await this.transport.send(message);
          }
        }
      } else {
        if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS not operational, sending plain message.`);
        await this.transport.send(message);
      }
      
      if (enableDiagnosticLogging) console.log(`${logPrefix}: Successfully sent to transport.`);
    } catch (error) {
      console.error(`${logPrefix}: Error sending message:`, error);
      throw error;
    }
  }

  // Forward transport properties
  get sessionId(): string | undefined { 
    return (this.transport as any).sessionId; 
  }

  // Handle HTTP POST for SSE transports (if applicable)
  async handlePostMessage?(req: IncomingMessage & { auth?: any }, res: ServerResponse, rawBodyString?: string): Promise<void> {
    const logPrefix = `[${this.proxyId}] HTTP_POST`;
    
    if (!('handlePostMessage' in this.transport) || typeof this.transport.handlePostMessage !== 'function') {
      console.error(`${logPrefix}: Underlying transport does not support handlePostMessage`);
      if (!res.writableEnded) res.writeHead(500).end("Transport does not support POST handling");
      return;
    }

    let bodyToProcess: string;
    if (rawBodyString !== undefined) {
      bodyToProcess = rawBodyString;
    } else {
      const bodyBuffer = [];
      for await (const chunk of req) { bodyBuffer.push(chunk); }
      bodyToProcess = Buffer.concat(bodyBuffer).toString();
      if (!bodyToProcess) {
        if (!res.writableEnded) res.writeHead(400).end("Empty body");
        return;
      }
    }

    if (enableDiagnosticLogging) console.log(`${logPrefix}: Raw body (len ${bodyToProcess.length}): ${bodyToProcess.substring(0,100)}...`);

    // Add this debug line before calling jacs.verifyResponse:
    console.log(`${logPrefix}: JACS Debug - Body type: ${typeof bodyToProcess}`);
    console.log(`${logPrefix}: JACS Debug - First 200 chars:`, JSON.stringify(bodyToProcess.substring(0, 200)));
    console.log(`${logPrefix}: JACS Debug - Is valid JSON?`, (() => {
      try { JSON.parse(bodyToProcess); return true; } catch { return false; }
    })());

    try {
      let processedBody = bodyToProcess;

      if (this.jacsOperational) {
        // Try normalizing the JSON string before JACS verification:
        try {
          // First, try to parse and re-stringify to normalize
          const parsedJson = JSON.parse(bodyToProcess);
          const normalizedJsonString = JSON.stringify(parsedJson);
          
          if (enableDiagnosticLogging) console.log(`${logPrefix}: Attempting JACS verification with normalized JSON...`);
          const verificationResult = await jacs.verifyResponse(normalizedJsonString);
          
          let decryptedMessage: JSONRPCMessage;
          if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
            decryptedMessage = verificationResult.payload as JSONRPCMessage;
          } else {
            decryptedMessage = verificationResult as JSONRPCMessage;
          }
          
          // Convert back to JSON string for the underlying transport
          processedBody = JSON.stringify(decryptedMessage);
          if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS verification successful. Decrypted to: ${processedBody.substring(0,100)}...`);
        } catch (parseError) {
          // If it's not valid JSON, try with original string
          if (enableDiagnosticLogging) console.log(`${logPrefix}: JSON normalization failed, trying original string...`);
          const verificationResult = await jacs.verifyResponse(bodyToProcess);
          
          let decryptedMessage: JSONRPCMessage;
          if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
            decryptedMessage = verificationResult.payload as JSONRPCMessage;
          } else {
            decryptedMessage = verificationResult as JSONRPCMessage;
          }
          
          // Convert back to JSON string for the underlying transport
          processedBody = JSON.stringify(decryptedMessage);
          if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS verification successful. Decrypted to: ${processedBody.substring(0,100)}...`);
        }
      }

      // Forward to underlying transport's POST handler
      await this.transport.handlePostMessage(req, res, processedBody);
      
    } catch (error) {
      console.error(`${logPrefix}: Error processing POST:`, error);
      if (!res.writableEnded) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error";
        res.writeHead(500).end(`Error: ${errorMessage}`);
      }
    }
  }
}

// Factory functions
export function createJACSTransportProxy(
  transport: Transport, 
  configPath: string,
  role: "client" | "server"
): JACSTransportProxy {
  console.log(`Creating JACS Transport Proxy for role: ${role}`);
  return new JACSTransportProxy(transport, role, configPath);
}

export async function createJACSTransportProxyAsync(
  transport: Transport,
  configPath: string,
  role: "client" | "server"
): Promise<JACSTransportProxy> {
  console.log(`Creating JACS Transport Proxy (async) for role: ${role}`);
  await ensureJacsLoaded(configPath);
  return new JACSTransportProxy(transport, role, configPath);
}