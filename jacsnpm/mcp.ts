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

// NEW jacsSignTransform: Wraps payload into params/result and "signs" the payload. Returns a new JSONRPCMessage.
async function jacsSignTransform(message: JSONRPCMessage): Promise<JSONRPCMessage> {
    if (!jacsLoaded) {
        console.error("jacsSignTransform: JACS not loaded. Cannot sign.");
        throw new Error("JACS_NOT_LOADED_CANNOT_SIGN");
    }

    let payload_to_sign: any;
    let message_category: 'request' | 'response' | 'notification' | 'error_response' | 'unknown' = 'unknown';
    // Safely get original_message_id. 'id' is optional on JSONRPCRequest (for notifications) and present on JSONRPCResponse.
    const original_message_id = ('id' in message && message.id !== null && typeof message.id !== 'undefined') ? message.id : undefined;

    if ('method' in message) { // It's a request or a notification
        // JSONRPCRequest can have an optional id. If id is missing, it's a notification.
        if ('id' in message && message.id !== null && typeof message.id !== 'undefined') { // It's a request expecting a response
            payload_to_sign = message.params ?? {}; 
            message_category = 'request';
        } else { // It's a notification (no id or id is null/undefined)
            payload_to_sign = message.params ?? {}; 
            message_category = 'notification';
        }
    } else if ('id' in message && message.id !== null && typeof message.id !== 'undefined') { // It's a response (must have id, no method)
        if ('result' in message && !('error' in message)) { // Success response
            payload_to_sign = message.result ?? {}; 
            message_category = 'response';
        } else if ('error' in message) { // Error response
            // Error responses are not JACS-wrapped with this scheme.
            if (enableDiagnosticLogging) console.log(`jacsSignTransform: JSON-RPC Error response (ID: ${original_message_id}). Passing through without JACS wrapper.`);
            return message;
        } else {
            // Invalid response: has id, no method, but neither result nor error
            console.warn(`jacsSignTransform: Invalid JSON-RPC Response (ID: ${original_message_id}). No result or error. Message: ${JSON.stringify(message).substring(0,150)}... Passing through.`);
            return message;
        }
    } else {
        // Unknown: no method and no id (or id is null/undefined for a non-request). This shouldn't be a valid JSON-RPC message.
        console.warn(`jacsSignTransform: Unknown message type for JACS signing. Message: ${JSON.stringify(message).substring(0,150)}... Passing through.`);
        return message;
    }

    // If message_category is still 'unknown' here, it means it was a request/notification/response
    // that was validly categorized but for which payload_to_sign ended up undefined (e.g. request with no params).
    // The earlier returns handle true "unknowns" or error pass-throughs.
    // If payload_to_sign is undefined for a valid category (e.g. request with no params), 
    // we should still proceed to sign an empty object as per `?? {}` above.

    try {
        if (enableDiagnosticLogging) console.log(`jacsSignTransform: Payload for JACS signing (ID: ${original_message_id}, Type: ${message_category}): ${JSON.stringify(payload_to_sign).substring(0,100)}...`);
        
        const jacs_artifact = await jacs.signRequest(payload_to_sign); 
        
        if (enableDiagnosticLogging) console.log(`jacsSignTransform: JACS artifact from signing (ID: ${original_message_id}): ${JSON.stringify(jacs_artifact).substring(0,100)}...`);

        const jacsWrapper = {
            jacs_artifact: jacs_artifact, 
            original_payload: payload_to_sign 
        };

        const newMessage = { ...message };

        if (message_category === 'request') {
            (newMessage as JSONRPCRequest).params = { jacs_wrapper: jacsWrapper };
        } else if (message_category === 'notification') {
            (newMessage as JSONRPCNotification).params = { jacs_wrapper: jacsWrapper };
        } else if (message_category === 'response') {
            (newMessage as (JSONRPCResponse & { result: any })).result = { jacs_wrapper: jacsWrapper };
        }
        
        if (enableDiagnosticLogging) console.log(`jacsSignTransform: New message with JACS wrapper (ID: ${original_message_id}): ${JSON.stringify(newMessage).substring(0, 200)}...`);
        return newMessage;

    } catch (error) {
        console.error(`jacsSignTransform: JACS signing of payload failed (ID: ${original_message_id}, Type: ${message_category}). Error:`, error);
        throw error;
    }
}

// NEW jacsVerifyTransform: Expects a JSONRPCMessage, unwraps and verifies JACS wrapper from params/result.
async function jacsVerifyTransform(message: JSONRPCMessage): Promise<JSONRPCMessage> {
    if (!jacsLoaded) {
        console.error("jacsVerifyTransform: JACS not loaded. Cannot verify.");
        throw new Error("JACS_NOT_LOADED_CANNOT_VERIFY");
    }

    let jacsWrapperSource: any;
    let message_category: 'request' | 'response' | 'notification' | 'unknown' = 'unknown';
    let original_message_id = 'id' in message ? message.id : undefined;

    if (isJSONRPCRequest(message) && message.params && typeof message.params.jacs_wrapper === 'object') {
        jacsWrapperSource = message.params.jacs_wrapper;
        message_category = 'request';
    } else if (isJSONRPCResponse(message) && !('error' in message) && message.result && typeof message.result.jacs_wrapper === 'object') {
        jacsWrapperSource = message.result.jacs_wrapper;
        message_category = 'response';
    } else if (isJSONRPCNotification(message) && message.params && typeof message.params.jacs_wrapper === 'object') {
        jacsWrapperSource = message.params.jacs_wrapper;
        message_category = 'notification';
    } else {
        if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: No JACS wrapper in params/result (ID: ${original_message_id}, Type: ${message.hasOwnProperty('method')? 'req/notif' : 'resp'}). Passing through. Content: ${JSON.stringify(message).substring(0,100)}`);
        return message; // Not a wrapped message or an error response
    }
    
    const { jacs_artifact, original_payload } = jacsWrapperSource;

    if (typeof jacs_artifact === 'undefined' /* || typeof original_payload === 'undefined' */) { // original_payload might not be needed by verifyResponse directly
        console.error(`jacsVerifyTransform: Invalid JACS wrapper structure (ID: ${original_message_id}). Missing artifact. Wrapper:`, jacsWrapperSource);
        throw new Error("Invalid JACS wrapper in message, missing artifact");
    }

    try {
        // The jacs_artifact is what the native code likely expects.
        // If jacs_artifact is an object, it might need to be stringified if the native function expects a string.
        // For now, let's assume jacs_artifact is already in the correct format (string or object) expected by jacs.verifyResponse
        // The error states verifyResponse expects a string. So jacs_artifact should be a string.
        
        const artifactToVerify = typeof jacs_artifact === 'string' ? jacs_artifact : JSON.stringify(jacs_artifact);

        if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Input TO NATIVE jacs.verifyResponse (ID: ${original_message_id}): ${String(artifactToVerify).substring(0,150)}...`);
        
        // Assume jacs.verifyResponse returns the verified payload if successful, or throws on error.
        // It now receives the jacs_artifact (expected to be a string or stringifiable)
        const verifiedPayload = await jacs.verifyResponse(artifactToVerify); 
        
        if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: NATIVE jacs.verifyResponse SUCCEEDED (ID: ${original_message_id}). Returned: ${JSON.stringify(verifiedPayload).substring(0,100)}...`);

        // Basic check: if native returns something, and it's an object (payloads are objects)
        if (typeof verifiedPayload !== 'object' || verifiedPayload === null) {
             console.error(`jacsVerifyTransform: Native jacs.verifyResponse did not return a valid object payload (ID: ${original_message_id}). Got:`, verifiedPayload);
             throw new Error("JACS verification failed to return valid payload object.");
        }
        // More robust check (optional): deep compare verifiedPayload and original_payload if native is expected to return original on success.
        // For now, trust that if no error is thrown and an object is returned, it's the verified original_payload.

        const unwrappedMessage = { ...message };
        if (message_category === 'request') {
            (unwrappedMessage as JSONRPCRequest).params = verifiedPayload as { [x: string]: unknown; };
        } else if (message_category === 'notification') {
            (unwrappedMessage as JSONRPCNotification).params = verifiedPayload as { [x: string]: unknown; };
        } else if (message_category === 'response') {
            // Assert that unwrappedMessage is a success response (has a result property)
            (unwrappedMessage as (JSONRPCResponse & { result: any })).result = verifiedPayload;
        }
        
        if (enableDiagnosticLogging) console.log(`jacsVerifyTransform: Successfully verified and unwrapped (ID: ${original_message_id}). New message: ${JSON.stringify(unwrappedMessage).substring(0,200)}...`);
        return unwrappedMessage;

    } catch (error) {
        console.error(`jacsVerifyTransform: JACS verification of payload failed (ID: ${original_message_id}). Error:`, error);
        throw error;
    }
}

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
      if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Received raw from transport. Type: ${typeof messageOrStringFromTransport}`);
      
      let messageObject: JSONRPCMessage;
      try {
        if (typeof messageOrStringFromTransport === 'string') {
            messageObject = JSON.parse(messageOrStringFromTransport) as JSONRPCMessage;
        } else if (typeof messageOrStringFromTransport === 'object' && messageOrStringFromTransport !== null && 'jsonrpc' in messageOrStringFromTransport) {
            messageObject = messageOrStringFromTransport as JSONRPCMessage;
        } else {
            console.error(`${startLogPrefix}: Received unexpected data type from transport`, messageOrStringFromTransport);
            throw new Error("Invalid data type from transport");
        }
        
        if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Parsed to JS object: ${JSON.stringify(messageObject).substring(0,100)}...`);
        
        let processedMessage: JSONRPCMessage = messageObject;

        if (this.incomingJacsTransformer && this.jacsOperational) {
            if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS op, applying incomingJacsTransformer (obj->obj).`);
            processedMessage = await this.incomingJacsTransformer(messageObject);
            if (enableDiagnosticLogging) console.log(`${startLogPrefix}: incomingJacsTransformer completed.`);
        } else { 
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS NOT op or no TX. Using parsed message as is.`);
        }
        
        if (this.onmessage) {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Passing processed message to SDK's onmessage.`);
          this.onmessage(processedMessage);
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: SDK's onmessage returned.`);
        } else {
            console.error(`${startLogPrefix}: CRITICAL - No SDK onmessage handler!`);
        }
      } catch (error) {
        const err = error as Error;
        console.error(`${startLogPrefix}: Error. Err: ${err.message}`, err.stack);
        if (this.onerror) this.onerror(err);
      }
    };
    this.transport.onclose = () => { if(this.onclose) this.onclose(); };
    this.transport.onerror = (error) => { if(this.onerror) this.onerror(error); };
    console.log(`[${this.middlewareId}] CONSTRUCTOR: Attached transport events.`);
  }

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  async start(): Promise<void> { return this.transport.start(); }
  async close(): Promise<void> { return this.transport.close(); }

  async send(message: JSONRPCMessage): Promise<void> {
    const startLogPrefix = `[${this.middlewareId}] SEND`;
    if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Original msg (ID: ${'id' in message ? message.id : 'N/A'}): ${JSON.stringify(message).substring(0,100)}...`);
    let messageToSend: JSONRPCMessage = message;

    try {
      if (this.outgoingJacsTransformer && this.jacsOperational) {
        if (isJSONRPCResponse(message) && 'error' in message) {
             if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Error response. Bypassing JACS transform.`);
        } else {
            if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS op, applying outgoingJacsTransformer (obj->obj).`);
            messageToSend = await this.outgoingJacsTransformer(message); 
            if (enableDiagnosticLogging) console.log(`${startLogPrefix}: outgoingJacsTransformer completed. Transformed Msg (ID: ${'id' in messageToSend ? messageToSend.id : 'N/A'}): ${JSON.stringify(messageToSend).substring(0,100)}...`);
        }
      } else {
          if (enableDiagnosticLogging) console.log(`${startLogPrefix}: JACS NOT op or no TX. Sending original message object.`);
      }
      
      const endpointProperty = (messageToSend as any).endpoint;
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
      
      if (this.middlewareId === "SERVER_MIDDLEWARE" && typeof (this.transport as any)._sseResponse !== 'undefined') {
        const sseResponse = (this.transport as any)._sseResponse;
        if (!sseResponse) throw new Error("Server SSE connection not established"); // Should be caught by the undefined check, but good practice
        const payloadStringForTransport = JSON.stringify(messageToSend);
        if (enableDiagnosticLogging) console.log(`${startLogPrefix} (SSE Server): Sending event: message, data: ${payloadStringForTransport.substring(0,100)}...`);
        sseResponse.write(`event: message\ndata: ${payloadStringForTransport}\n\n`);
      } else { 
        // For CLIENT_MIDDLEWARE and any other Non-SSE Server transport, send the object.
        // The underlying transport.send() is responsible for any necessary serialization.
        if (enableDiagnosticLogging) console.log(`${startLogPrefix} (Client or Non-SSE Server): Sending object to transport.send: ${JSON.stringify(messageToSend).substring(0,100)}...`);
        await this.transport.send(messageToSend); 
      }
      
      if (enableDiagnosticLogging) console.log(`${startLogPrefix}: Successfully dispatched to underlying transport.`);
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
            if (isJSONRPCResponse(messageObjectFromPost) && 'error' in messageObjectFromPost){
                if (enableDiagnosticLogging) console.log(`${logPrefix}: Error response in POST. Bypassing JACS verify.`);
            } else {
                if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS op. Calling incomingJacsTransformer (obj->obj).`);
                messageForSDK = await this.incomingJacsTransformer(messageObjectFromPost);
                if (enableDiagnosticLogging) console.log(`${logPrefix}: incomingJacsTransformer completed.`);
            }
        } else {
            if (enableDiagnosticLogging) console.log(`${logPrefix}: JACS not op/no TX. Using parsed POST obj as is.`);
        }
        
        if (this.onmessage) {
            this.onmessage(messageForSDK); 
        } else {
            console.error(`${logPrefix}: CRITICAL - No onmessage handler for POST.`);
            if (!res.writableEnded) res.writeHead(500).end("Server error: no handler");
            return;
        }
        if (!res.writableEnded) res.writeHead(202).end();
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
  console.log(`Creating JACS Middleware (sync init) for role: ${role} with new obj->obj transformers.`);
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