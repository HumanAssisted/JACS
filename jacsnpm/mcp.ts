// middleware.ts
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { 
    JSONRPCMessage, JSONRPCError, JSONRPCRequest, JSONRPCNotification, JSONRPCResponse,
    isJSONRPCRequest, isJSONRPCResponse, isJSONRPCNotification, ErrorCode 
} from "@modelcontextprotocol/sdk/types.js";
import jacs from './index.js'; // Assuming this has { signRequest: (data: any) => Promise<any>, verifyResponse: (data: any) => Promise<any> }
import { IncomingMessage, ServerResponse } from "node:http";

// Load JACS config only once
let jacsLoaded = false;
let jacsLoadError: Error | null = null;

async function ensureJacsLoaded(configPath: string): Promise<void> {
  if (jacsLoaded) return; // If successfully loaded, nothing to do.
  if (jacsLoadError) throw jacsLoadError; // If previously failed, re-throw the known error.

  try {
    console.log(`ensureJacsLoaded: Attempting to load JACS config from: ${configPath}`);
    // Reset jacsLoadError before attempting to load
    jacsLoadError = null; 
    await jacs.load(configPath);
    jacsLoaded = true;
    console.log(`ensureJacsLoaded: JACS agent loaded successfully from ${configPath}.`);
  } catch (error) {
    jacsLoadError = error as Error;
    // Log the detailed error here immediately when it happens
    console.error(`ensureJacsLoaded: CRITICAL: Failed to load JACS config from '${configPath}'. Error:`, jacsLoadError.message, jacsLoadError.stack); 
    throw jacsLoadError; // Re-throw to ensure the failure propagates
  }
}

const enableDiagnosticLogging = process.env.JACS_MCP_DEBUG === 'true';
// Corrected JACS transforms based on actual JACS behavior and MCP transport requirements
// Corrected JACS transforms based on actual JACS behavior and MCP transport requirements

async function jacsSignTransform(message: JSONRPCMessage): Promise<JSONRPCMessage> {
  if (!jacsLoaded) {
      console.error("jacsSignTransform: JACS not loaded. Cannot sign.");
      throw new Error("JACS_NOT_LOADED_CANNOT_SIGN");
  }

  const original_message_id = ('id' in message && message.id !== null && typeof message.id !== 'undefined') ? message.id : undefined;

  // Skip signing error responses - pass them through unchanged
  if ('error' in message) {
      if (enableDiagnosticLogging) console.log(`jacsSignTransform: JSON-RPC Error response (ID: ${original_message_id}). Passing through without JACS wrapper.`);
      return message;
  }

  try {
      if (enableDiagnosticLogging) console.log(`jacsSignTransform: Input TO jacs.signRequest (type ${typeof message}): ${JSON.stringify(message).substring(0,100)}...`);
      
      // Sign the ENTIRE JSON-RPC message as the payload
      const jacs_artifact = await jacs.signRequest(message); 
      
      if (enableDiagnosticLogging) console.log(`jacsSignTransform: Output FROM jacs.signRequest (type ${typeof jacs_artifact}): ${JSON.stringify(jacs_artifact).substring(0,150)}...`);

      // JACS returns a complete object structure, not just a string
      // We need to wrap this in a JSON-RPC envelope that MCP transport can handle
      const wrappedMessage: JSONRPCMessage = {
          jsonrpc: "2.0",
          method: "jacs/wrapped",
          params: {
              jacs_artifact: jacs_artifact
          }
      };

      // Preserve the original message ID if it exists
      if (original_message_id !== undefined) {
          (wrappedMessage as any).id = original_message_id;
      }
      
      if (enableDiagnosticLogging) console.log(`jacsSignTransform: Created wrapped JSON-RPC message (ID: ${original_message_id}): ${JSON.stringify(wrappedMessage).substring(0, 200)}...`);
      return wrappedMessage;

  } catch (error) {
      console.error(`jacsSignTransform: JACS signing failed (ID: ${original_message_id}). Error:`, error);
      throw error;
  }
}

async function jacsVerifyTransform(message: JSONRPCMessage): Promise<JSONRPCMessage> {
  if (!jacsLoaded) {
      console.error("jacsVerifyTransform: JACS not loaded. Cannot verify.");
      throw new Error("JACS_NOT_LOADED_CANNOT_VERIFY");
  }

  const original_message_id = 'id' in message ? message.id : undefined;

  // Check if this is a JACS-wrapped message
  if (!('method' in message) || message.method !== 'jacs/wrapped' || !message.params || typeof message.params.jacs_artifact === 'undefined') {
      if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Not a JACS-wrapped message (ID: ${original_message_id}). Method: ${(message as any).method || 'none'}. Passing through.`);
      return message; // Not a JACS-wrapped message, pass through
  }

  const jacs_artifact = message.params.jacs_artifact;

  try {
      // Convert jacs_artifact to string format that jacs.verifyResponse expects
      let artifactToVerify: string;
      if (typeof jacs_artifact === 'string') {
          artifactToVerify = jacs_artifact;
      } else if (jacs_artifact && typeof jacs_artifact === 'object') {
          artifactToVerify = JSON.stringify(jacs_artifact);
      } else {
          console.error(`jacsVerifyTransform: Invalid jacs_artifact type (${typeof jacs_artifact}):`, jacs_artifact);
          throw new Error("JACS artifact is not a valid string or object");
      }

      if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Input TO jacs.verifyResponse (type ${typeof artifactToVerify}, length ${artifactToVerify.length}): ${artifactToVerify.substring(0,150)}...`);
      
      // jacs.verifyResponse expects a string parameter according to TypeScript
      const verificationResult = await jacs.verifyResponse(artifactToVerify); 
      
      if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Output FROM jacs.verifyResponse (type ${typeof verificationResult}): ${JSON.stringify(verificationResult).substring(0,100)}...`);

      // Extract the original message from the verification result
      let originalMessage: JSONRPCMessage;
      
      if (verificationResult && typeof verificationResult === 'object') {
          // Check if verifyResponse returns an object with a payload property
          if ('payload' in verificationResult) {
              originalMessage = verificationResult.payload as JSONRPCMessage;
              if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Extracted from verificationResult.payload`);
          } else {
              // If verifyResponse returns the payload directly
              originalMessage = verificationResult as JSONRPCMessage;
              if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Using verificationResult directly`);
          }
      } else {
          console.error(`jacsVerifyTransform: JACS verification returned invalid data (type: ${typeof verificationResult}):`, verificationResult);
          throw new Error("JACS verification failed to return valid object.");
      }

      // Validate that we got back a proper JSON-RPC message
      if (!originalMessage || typeof originalMessage !== 'object' || originalMessage.jsonrpc !== '2.0') {
          console.error(`jacsVerifyTransform: Verified payload is not a valid JSON-RPC message. Got (type: ${typeof originalMessage}):`, originalMessage);
          throw new Error("JACS verification did not return a valid JSON-RPC message.");
      }
      
      if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: SUCCESSFULLY VERIFIED. Returning original JSON-RPC message: ${JSON.stringify(originalMessage).substring(0,200)}...`);
      return originalMessage;

  } catch (error) {
      console.error(`jacsVerifyTransform: JACS verification failed (ID: ${original_message_id}). JACS artifact was: ${JSON.stringify(jacs_artifact).substring(0,100)}... Error:`, error);
      throw error;
  }
}

// Updated TransportMiddleware to handle JSON-RPC message objects (not strings)
export class TransportMiddleware implements Transport {
private jacsOperational = true;
private middlewareId: "CLIENT_MIDDLEWARE" | "SERVER_MIDDLEWARE";

constructor(
  private transport: Transport,
  role: "client" | "server",
  private outgoingJacsTransformer?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage>,
  private incomingJacsTransformer?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage>,
  private jacsConfigPath?: string
) {
  this.middlewareId = role === "client" ? "CLIENT_MIDDLEWARE" : "SERVER_MIDDLEWARE";
  console.log(`[${this.middlewareId}] CONSTRUCTOR: Role: ${role}. JACS Config: ${jacsConfigPath}`);

  if (jacsConfigPath) {
    ensureJacsLoaded(jacsConfigPath)
      .then(() => { this.jacsOperational = true; console.log(`[${this.middlewareId}] JACS Loaded.`); })
      .catch(err => { this.jacsOperational = false; console.error(`[${this.middlewareId}] JACS Load FAILED:`, err.message); });
  } else {
    this.jacsOperational = false;
    console.warn(`[${this.middlewareId}] No JACS config. JACS Non-Operational.`);
  }

  this.transport.onmessage = async (messageOrStringFromTransport: string | JSONRPCMessage | object) => {
    const startLogPrefix = `[${this.middlewareId}] ONMESSAGE_HANDLER (transport.onmessage)`;
    if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Received raw from transport. Type: ${typeof messageOrStringFromTransport}, Content: ${String(messageOrStringFromTransport).substring(0,100)}...`);
    
    let messageObject: JSONRPCMessage;
    try {
      if (typeof messageOrStringFromTransport === 'string') {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Parsing string as JSON.`);
          messageObject = JSON.parse(messageOrStringFromTransport) as JSONRPCMessage;
      } else if (typeof messageOrStringFromTransport === 'object' && messageOrStringFromTransport !== null && 'jsonrpc' in messageOrStringFromTransport) {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Received object, using as-is.`);
          messageObject = messageOrStringFromTransport as JSONRPCMessage;
      } else {
          console.error(`${startLogPrefix}: Received unexpected data type from transport:`, typeof messageOrStringFromTransport, messageOrStringFromTransport);
          throw new Error("Invalid data type from transport");
      }
      
      if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Parsed message object: ${JSON.stringify(messageObject).substring(0,100)}...`);
      
      let processedMessage: JSONRPCMessage = messageObject;

      if (this.incomingJacsTransformer && this.jacsOperational) {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS operational, applying incomingJacsTransformer (obj->obj).`);
          processedMessage = await this.incomingJacsTransformer(messageObject);
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: incomingJacsTransformer completed successfully.`);
      } else {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS not operational or no transformer. Using parsed message as-is.`);
      }
      
      if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Final processed message: ${JSON.stringify(processedMessage).substring(0,100)}...`);
      
      if (this.onmessage) {
        if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Passing processed message to SDK's onmessage.`);
        this.onmessage(processedMessage);
        if (enableDiagnosticLogging) console.log(`${startLogPrefix}: SDK's onmessage returned successfully.`);
      } else {
          console.error(`${startLogPrefix}: CRITICAL - No SDK onmessage handler!`);
      }
    } catch (error) {
      const err = error as Error;
      console.error(`${startLogPrefix}: Error processing message. Err: ${err.message}`, err.stack);
      if (this.onerror) this.onerror(err);
    }
  };
  
  this.transport.onclose = () => { 
    console.log(`[${this.middlewareId}] Transport closed.`);
    if(this.onclose) this.onclose(); 
  };
  this.transport.onerror = (error) => { 
    console.error(`[${this.middlewareId}] Transport error:`, error);
    if(this.onerror) this.onerror(error); 
  };
  console.log(`[${this.middlewareId}] CONSTRUCTOR: Attached transport events.`);
}

onclose?: () => void;
onerror?: (error: Error) => void;
onmessage?: (message: JSONRPCMessage) => void;

async start(): Promise<void> { 
  console.log(`[${this.middlewareId}] Starting transport...`);
  return this.transport.start(); 
}

async close(): Promise<void> { 
  console.log(`[${this.middlewareId}] Closing transport...`);
  return this.transport.close(); 
}

async send(message: JSONRPCMessage): Promise<void> {
  const startLogPrefix = `[${this.middlewareId}] SEND`;
  if (enableDiagnosticLogging) console.log(`${startLogPrefix}: ABOUT TO SEND. Original msg (ID: ${'id' in message ? message.id : 'N/A'}): ${JSON.stringify(message).substring(0,100)}...`);

  try {
    let messageToSend: JSONRPCMessage = message;

    if (this.outgoingJacsTransformer && this.jacsOperational) {
      if (isJSONRPCResponse(message) && 'error' in message) {
           if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Error response detected. Bypassing JACS transform.`);
      } else {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS operational, applying outgoingJacsTransformer (obj->obj).`);
          messageToSend = await this.outgoingJacsTransformer(message); 
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: outgoingJacsTransformer completed. Transformed message: ${JSON.stringify(messageToSend).substring(0,100)}...`);
      }
    } else {
        if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS not operational, sending original message.`);
    }
    
    const endpointProperty = (message as any).endpoint;
    if (this.middlewareId === "SERVER_MIDDLEWARE" && typeof endpointProperty === 'string') {
      if (enableDiagnosticLogging) console.log(`${startLogPrefix} (SSE Server): Detected 'endpoint' event. Value: ${endpointProperty}`);
      // Ensure _sseResponse is available and a ServerResponse (or similar with .write)
      const sseTransport = this.transport as any; 
      if (sseTransport._sseResponse && typeof sseTransport._sseResponse.write === 'function') {
          sseTransport._sseResponse.write(`event: endpoint\ndata: ${endpointProperty}\n\n`);
          if (enableDiagnosticLogging) console.log(`${startLogPrefix} (SSE Server): 'endpoint' event sent.`);
      } else {
          console.warn(`${startLogPrefix} (SSE Server): _sseResponse not available or no write method for sending 'endpoint' event.`);
      }
      return;
    }
    
    // Send to underlying transport - MCP SDK expects JSON-RPC objects
    if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Calling underlying transport.send() with message type: ${typeof messageToSend}`);
    await this.transport.send(messageToSend); 
    
    if (enableDiagnosticLogging) console.log(`${startLogPrefix}: SUCCESSFULLY SENT.`);
  } catch (error) {
    const err = error as Error;
    console.error(`${startLogPrefix}: CAUGHT ERROR: ${err.message}`, err.stack);
    throw err; 
  }
}

get sessionId(): string | undefined { return (this.transport as any).sessionId; }

async handlePostMessage(req: IncomingMessage & { auth?: any }, res: ServerResponse, rawBodyString?: string): Promise<void> {
  const logPrefix = `[${this.middlewareId} HTTP_POST_HANDLER]`;
  let bodyToProcess: string;
  if (rawBodyString !== undefined && typeof rawBodyString === 'string') {
      bodyToProcess = rawBodyString;
  } else {
      const bodyBuffer = []; for await (const chunk of req) { bodyBuffer.push(chunk); }
      bodyToProcess = Buffer.concat(bodyBuffer).toString();
      if (!bodyToProcess) { if (!res.writableEnded) res.writeHead(400).end("Empty body."); return; }
  }
  if (enableDiagnosticLogging) console.log(`${logPrefix}: Raw POST body (len ${bodyToProcess?.length}): ${bodyToProcess?.substring(0,100)}...`);

  try {
      let messageObjectFromPost = JSON.parse(bodyToProcess) as JSONRPCMessage;
      if (enableDiagnosticLogging) console.log(`${logPrefix}: Parsed POST to object: ${JSON.stringify(messageObjectFromPost).substring(0,100)}...`);
      let messageForSDK: JSONRPCMessage = messageObjectFromPost;

      if (this.jacsOperational && this.incomingJacsTransformer) {
          if (isJSONRPCResponse(messageObjectFromPost) && 'error' in messageObjectFromPost) {
              if (enableDiagnosticLogging) console.log(`${logPrefix}: Error response in POST. Bypassing JACS verify.`);
          } else {
              if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS operational. Calling incomingJacsTransformer (obj->obj).`);
              messageForSDK = await this.incomingJacsTransformer(messageObjectFromPost);
              if (enableDiagnosticLogging) console.log(`${logPrefix}: incomingJacsTransformer completed successfully.`);
          }
      } else {
          if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS not operational or no transformer. Using parsed POST obj as-is.`);
      }
      
      if (this.onmessage) {
          if (enableDiagnosticLogging) console.log(`${logPrefix}: Passing message to SDK's onmessage handler.`);
          this.onmessage(messageForSDK); 
          if (enableDiagnosticLogging) console.log(`${logPrefix}: SDK's onmessage handler completed.`);
      } else {
          console.error(`${logPrefix}: CRITICAL - No onmessage handler for POST.`);
          if (!res.writableEnded) res.writeHead(500).end("Server error: no handler");
          return;
      }
      if (!res.writableEnded) res.writeHead(202).end();
      if (enableDiagnosticLogging) console.log(`${logPrefix}: POST request processing completed successfully.`);
  } catch (error) {
      const err = error as Error;
      console.error(`${logPrefix}: Error in POST processing. Err: ${err.message}`, err.stack);
      if (!res.writableEnded) res.writeHead(400).end(`Err: ${err.message}`);
      if (this.onerror) this.onerror(err);
  }
}
}

export function createJacsMiddleware(
  transport: Transport, 
  configPath: string,
  role: "client" | "server"
): TransportMiddleware {
  console.log(`Creating JACS Middleware (sync init) for role: ${role} with complete message wrapping.`);
  return new TransportMiddleware(transport, role, jacsSignTransform, jacsVerifyTransform, configPath);
}

export async function createJacsMiddlewareAsync(
  transport: Transport,
  configPath: string,
  role: "client" | "server"
): Promise<TransportMiddleware> {
  console.log(`Creating JACS Middleware (async init) for role: ${role}. Ensuring JACS loaded first.`);
  await ensureJacsLoaded(configPath);    
  return new TransportMiddleware(transport, role, jacsSignTransform, jacsVerifyTransform, configPath);
}