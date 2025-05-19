// middleware.ts
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage, JSONRPCError, isJSONRPCRequest, isJSONRPCResponse, isJSONRPCNotification, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import jacs from './index.js';
import { IncomingMessage, ServerResponse } from "node:http";

// Load JACS config only once
let jacsLoaded = false;
let jacsLoadError: Error | null = null;

async function ensureJacsLoaded(configPath: string): Promise<void> {
  if (jacsLoaded) return; // If successfully loaded, nothing to do.
  if (jacsLoadError) throw jacsLoadError; // If previously failed, re-throw the known error.

  try {
    console.log(`Attempting to load JACS config from: ${configPath}`);
    // Reset jacsLoadError before attempting to load
    jacsLoadError = null; 
    await jacs.load(configPath);
    jacsLoaded = true;
    console.log("JACS agent loaded successfully.");
  } catch (error) {
    jacsLoadError = error as Error;
    // Log the detailed error here immediately when it happens
    console.error(`CRITICAL: Failed to load JACS configuration from '${configPath}'. Error:`, jacsLoadError.message, jacsLoadError.stack); 
    throw jacsLoadError; // Re-throw to ensure the failure propagates
  }
}

// Renaming for clarity: this transforms an outgoing JSONRPCMessage to a JACS string
async function jacsSignTransform(message: JSONRPCMessage): Promise<string> {
  if (!jacsLoaded) {
    console.error("jacsSignTransform: JACS not loaded. Cannot sign.");
    throw new Error("JACS_NOT_LOADED_CANNOT_SIGN");
  }
  try {
    console.log(`jacsSignTransform: Input TO jacs.signRequest (type ${typeof message}): ${JSON.stringify(message).substring(0, 200)}...`);
    const signedJacsString = await jacs.signRequest(message);
    console.log(`jacsSignTransform: Output FROM jacs.signRequest (type ${typeof signedJacsString}, length ${signedJacsString?.length}): ${signedJacsString?.substring(0, 200)}...`);
    if (typeof signedJacsString !== 'string') {
        console.error("CRITICAL: jacs.signRequest did NOT return a string!");
        throw new Error("jacs.signRequest did not return a string");
    }
    return signedJacsString;
  } catch (error) {
    console.error("jacsSignTransform: JACS signing failed. Input was (approx):", JSON.stringify(message).substring(0, 200), "Error:", error);
    throw error;
  }
}

const enableDiagnosticLogging = process.env.JACS_MCP_DEBUG === 'true';

// JACS Verification Transformer (string-to-object, or object-to-object if already parsed)
// This transformer takes a JACS string (or an already parsed JACS object),
// verifies it using the native jacs.verifyResponse, and returns the inner JSONRPCMessage.
async function jacsVerifyTransform(
    jacsInput: string | object, // Can be a JACS string or an already parsed JACS object
    direction: 'incoming' | 'outgoing', // for logging/context
    messageType: 'request' | 'response' | 'notification' | 'error' | 'unknown', // for logging/context
): Promise<JSONRPCMessage> {
    if (enableDiagnosticLogging) {
        console.log(`jacsVerifyTransform START (${direction} ${messageType}): Input type ${typeof jacsInput}. jacsLoaded: ${jacsLoaded}, jacsLoadError: ${jacsLoadError ? jacsLoadError.message : null}`);
    }

    // Check JACS operational status FIRST in the transformer
    if (!jacsLoaded) {
        console.error(`jacsVerifyTransform: JACS_NOT_LOADED. jacsLoaded is false.`);
        if (jacsLoadError) {
            console.error(`jacsVerifyTransform: JACS previously failed to load: ${jacsLoadError.message}`);
            throw new Error(`JACS_NOT_LOADED (previous load failure): ${jacsLoadError.message}`);
        }
        throw new Error("JACS_NOT_LOADED (jacsLoaded is false, no prior error recorded)");
    }
    if (jacsLoadError) { // Should be redundant if !jacsLoaded check is comprehensive, but good for safety
        console.error(`jacsVerifyTransform: JACS_LOAD_ERROR_PRESENT: ${jacsLoadError.message}`);
        throw new Error(`JACS_LOAD_ERROR_PRESENT: ${jacsLoadError.message}`);
    }

    let jacsObject: object; // This will be the JACS header object
    let verifiedPayloadObject: any; // This will hold the final JSONRPC message payload

    if (typeof jacsInput === 'string') {
        if (enableDiagnosticLogging) {
            console.log(`jacsVerifyTransform: Received string input (length ${jacsInput.length}). Attempting JSON.parse to get JACS header object.`);
            console.log(`jacsVerifyTransform: String sample: ${jacsInput.substring(0, 200)}...`);
        }
        try {
            jacsObject = JSON.parse(jacsInput); // Parse the incoming JACS string into an object
            if (enableDiagnosticLogging) {
                console.log(`jacsVerifyTransform: Successfully parsed JACS string into JACS header object.`);
            }
        } catch (jsParseError: any) {
            const errorMsg = `jacsVerifyTransform: Input JACS string is invalid JSON. Error: ${jsParseError.message}. Input (first 200 chars): ${jacsInput.substring(0, 200)}`;
            console.error(errorMsg);
            throw new Error(errorMsg);
        }
    } else if (typeof jacsInput === 'object' && jacsInput !== null) {
        jacsObject = jacsInput; // Input is already the JACS header object
        if (enableDiagnosticLogging) {
            console.log(`jacsVerifyTransform: Received object input (assumed to be JACS header object).`);
        }
    } else {
        const errorMsg = `jacsVerifyTransform: Invalid input type. Expected JACS string or JACS header object, got ${typeof jacsInput}.`;
        console.error(errorMsg, jacsInput);
        throw new Error(errorMsg);
    }

    let rawVerifiedOutput: any; 

    if (enableDiagnosticLogging) {
        console.log(`jacsVerifyTransform: JACS Header Object Input TO NATIVE jacs.verifyResponse (type object):`, JSON.stringify(jacsObject)?.substring(0,300));
    }

    try {
        rawVerifiedOutput = await (jacs.verifyResponse as any)(jacsObject);

        if (enableDiagnosticLogging) {
            console.log(`jacsVerifyTransform: NATIVE jacs.verifyResponse SUCCEEDED. Returned raw output type: ${typeof rawVerifiedOutput}`, JSON.stringify(rawVerifiedOutput)?.substring(0,300));
        }

        if (typeof rawVerifiedOutput !== 'object' || rawVerifiedOutput === null) {
            const errorMsg = `jacsVerifyTransform: NATIVE jacs.verifyResponse was expected to return an object, but got type ${typeof rawVerifiedOutput}.`;
            console.error(errorMsg, rawVerifiedOutput);
            throw new Error(errorMsg);
        }

        // Check if the actual payload is nested
        if ('payload' in rawVerifiedOutput && typeof rawVerifiedOutput.payload === 'object' && rawVerifiedOutput.payload !== null) {
            if (enableDiagnosticLogging) {
                console.log("jacsVerifyTransform: Detected 'payload' property in native response. Extracting it.");
            }
            verifiedPayloadObject = rawVerifiedOutput.payload; // Extract the nested payload
        } else {
            // Assume rawVerifiedOutput IS the payload if no 'payload' property found
             if (enableDiagnosticLogging) {
                console.log("jacsVerifyTransform: No 'payload' property in native response. Assuming raw output is the payload.");
            }
            verifiedPayloadObject = rawVerifiedOutput;
        }

        if (typeof verifiedPayloadObject !== 'object' || verifiedPayloadObject === null) {
            const errorMsg = `jacsVerifyTransform: Extracted payload is not an object or is null. Type: ${typeof verifiedPayloadObject}.`;
            console.error(errorMsg, verifiedPayloadObject);
            throw new Error(errorMsg);
        }

    } catch (nativeError: any) {
        const errorDetail = `Input JACS Header Object (passed to native verifyResponse) was (first 200 chars of stringified): ${JSON.stringify(jacsObject)?.substring(0, 200)}...`;
        // The nativeError.message here IS the "is not of type object" if it's still happening
        const errorMsg = `jacsVerifyTransform: NATIVE jacs.verifyResponse FAILED. ${errorDetail}. Native Error: ${nativeError.message || nativeError}`;
        console.error(errorMsg, nativeError);
        throw new Error(`Native jacs.verifyResponse failed: ${nativeError.message || nativeError}`);
    }

    if (typeof verifiedPayloadObject !== 'object' || verifiedPayloadObject === null) {
        const errorMsg = `jacsVerifyTransform: Final verified payload is not an object or is null after try/catch. Type: ${typeof verifiedPayloadObject}. This is unexpected.`;
        console.error(errorMsg, verifiedPayloadObject);
        throw new Error(errorMsg);
    }
    
    if (!('jsonrpc' in verifiedPayloadObject && verifiedPayloadObject.jsonrpc === '2.0')) {
         if (enableDiagnosticLogging) {
            console.warn(`jacsVerifyTransform: Final verified payload does not look like a standard JSONRPC message. Payload:`, JSON.stringify(verifiedPayloadObject));
        }
        // It's possible the native layer already confirmed it's JSON-RPC, but good to double check.
        // If it's truly not JSON-RPC, this will be an issue for the SDK.
    }

    return verifiedPayloadObject as JSONRPCMessage;
}

export class TransportMiddleware implements Transport {
  private jacsOperational = true;

  constructor(
    private transport: Transport,
    // For outgoing messages: transform JSONRPCMessage to JACS string
    private outgoingJacsTransformer?: (msg: JSONRPCMessage) => Promise<string>,
    // For incoming messages: transform JACS string to JSONRPCMessage
    private incomingJacsTransformer?: (jacsString: string) => Promise<JSONRPCMessage>,
    private jacsConfigPath?: string
  ) {
    if (jacsConfigPath) {
      ensureJacsLoaded(jacsConfigPath)
        .then(() => {
            this.jacsOperational = true; // Set true only on success
            console.log("TransportMiddleware: JACS loaded successfully via constructor call.");
        })
        .catch(err => {
            this.jacsOperational = false;
            // This log clearly indicates that JACS is not operational DUE TO A LOADING FAILURE.
            console.error("TransportMiddleware Constructor: ensureJacsLoaded FAILED, JACS will be NON-OPERATIONAL. Error:", err.message, err.stack);
            // It's important that this failure is noted, as subsequent operations might depend on jacsOperational
        });
    } else {
      this.jacsOperational = false; // Explicitly false if no path
      console.warn("TransportMiddleware: No JACS config path provided. JACS will be NON-OPERATIONAL.");
    }

    this.transport.onmessage = async (message: string | JSONRPCMessage) => {
      let requestId: string | number | null = null;
      try {
        console.log(`TransportMiddleware.onmessage: Raw incoming message type: ${typeof message}`);
        if (!this.jacsOperational && this.incomingJacsTransformer) {
             console.warn("TransportMiddleware.onmessage: JACS not operational, but incomingJacsTransformer is defined. This might lead to issues.");
        }
        
        let processedMessage: JSONRPCMessage;

        if (this.incomingJacsTransformer && this.jacsOperational) {
          if (typeof message === 'string') {
            console.log("TransportMiddleware.onmessage: Received string (expected for JACS SSE), applying incomingJacsTransformer.");
            processedMessage = await this.incomingJacsTransformer(message);
          } else {
            // If JACS is active, 'message' from transport (esp. SSE) MUST be the JACS string.
            // Receiving an object here means either it's not a JACS message, or a layer problem.
            throw new Error(`TransportMiddleware.onmessage: CRITICAL - JACS is active but received a pre-parsed object (type: ${typeof message}) when a JACS string was expected from the transport. This indicates a layer mismatch or a non-JACS message.`);
          }
        } else { // No JACS transformer or JACS not operational
          if (typeof message === 'string') {
            console.log("TransportMiddleware.onmessage: No JACS (or not operational). Parsing string as JSONRPCMessage.");
            processedMessage = JSON.parse(message) as JSONRPCMessage;
          } else if (typeof message === 'object' && message !== null) {
            console.log("TransportMiddleware.onmessage: No JACS (or not operational). Assuming object is JSONRPCMessage.");
            processedMessage = message as JSONRPCMessage;
          } else {
            throw new Error(`Unexpected message type: ${typeof message}`);
          }
        }
        
        if (processedMessage && 'id' in processedMessage) {
            requestId = processedMessage.id as string | number | null;
        }

        if (this.onmessage) {
          console.log(`TransportMiddleware.onmessage: Passing processed message to SDK: ${JSON.stringify(processedMessage).substring(0,100)}...`);
          this.onmessage(processedMessage);
        }

      } catch (error) {
        const err = error as Error;
        console.error("Error in TransportMiddleware.onmessage processing:", err.message, err.stack);
        
        const errorPayload: JSONRPCError["error"] = { code: ErrorCode.InternalError, message: `Middleware onmessage error: ${err.message}` };
        
        let errorResponse: JSONRPCError;
        const finalErrorId = requestId === null || requestId === undefined ? undefined : requestId;

        if (finalErrorId !== undefined) {
            errorResponse = {
                jsonrpc: "2.0",
                id: finalErrorId,
                error: errorPayload
            };
        } else {
            errorResponse = {
                jsonrpc: "2.0",
                id: null,
                error: errorPayload
            } as any;
        }
        
        try {
          await this.send(errorResponse);
        } catch (sendError) {
           console.error("TransportMiddleware.onmessage: CRITICAL - Failed to send error response via this.send:", sendError);
           try {
            const errPayload = typeof errorResponse === 'string' ? errorResponse : JSON.stringify(errorResponse);
            await this.transport.send(errPayload as any);
           } catch (rawSendError) {
            console.error("TransportMiddleware.onmessage: CRITICAL - Failed to send error response via direct transport.send:", rawSendError);
           }
        }
        if (this.onerror) {
          this.onerror(err);
        }
      }
    };
    
    this.transport.onclose = () => { if(this.onclose) this.onclose(); };
    this.transport.onerror = (error) => { if(this.onerror) this.onerror(error); };
  }

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  async start(): Promise<void> { return this.transport.start(); }
  async close(): Promise<void> { return this.transport.close(); }

  async send(message: JSONRPCMessage): Promise<void> {
    let messageForJacs = message;
    let transformedMessageString: string | null = null;
    let wasJacsTransformed = false; // Flag to know what was sent

    try {
      if (this.outgoingJacsTransformer && this.jacsOperational) {
        let skipJacsTransform = false;
        if (isJSONRPCResponse(messageForJacs) && 
            'error' in messageForJacs && 
            messageForJacs.error && 
            typeof messageForJacs.error === 'object' &&
            'message' in messageForJacs.error &&
            typeof messageForJacs.error.message === 'string'
           ) {
            if (messageForJacs.error.message.includes("JACS_NOT_LOADED") || 
                messageForJacs.error.message.includes("JACS signing failed") ||
                messageForJacs.error.message.includes("JACS_NOT_OPERATIONAL") ||
                messageForJacs.error.message.includes("Native jacs.verifyResponse failed")) {
                console.warn("TransportMiddleware.send: Error message indicates JACS issue, sending error as plain JSON-RPC.");
                skipJacsTransform = true;
            }
        }

        if (!skipJacsTransform) {
            transformedMessageString = await this.outgoingJacsTransformer(messageForJacs);
            wasJacsTransformed = true; 
        }
      }
      
      const payloadForTransport = transformedMessageString ?? JSON.stringify(messageForJacs);
      
      // UNCONDITIONAL LOG
      console.log(`[UNCONDITIONAL] TransportMiddleware.send: ABOUT TO SEND. Was JACS: ${wasJacsTransformed}, Len: ${payloadForTransport.length}, Payload: ${payloadForTransport.substring(0,100)}...`);
      
      await this.transport.send(payloadForTransport as any);
      
      // UNCONDITIONAL LOG
      console.log(`[UNCONDITIONAL] TransportMiddleware.send: SUCCESSFULLY SENT.`);

    } catch (error) {
      const err = error as Error;
      // UNCONDITIONAL LOG
      console.error("[UNCONDITIONAL] TransportMiddleware.send: CAUGHT ERROR:", err.message, err.stack);
      if (err.message?.includes("JACS_NOT_LOADED") || err.message?.includes("JACS signing failed") || !this.jacsOperational || err.message.includes("Native jacs.verifyResponse failed")) {
          console.error("Error in TransportMiddleware.send (JACS related, will not attempt to send JACS error response):", err.message);
          
          let isSendingJacsNotLoadedError = false;
          // Check if 'message' is an object and has an 'error' property.
          // Also ensure 'message' itself is not null or undefined.
          if (message && typeof message === 'object' && 'error' in message && message.error) { 
            // Now TypeScript knows message has an 'error' property, 
            // and we've checked message.error is truthy.
            // We also need to ensure err.message is a string before calling .includes()
            if (err.message && err.message.includes("JACS_NOT_LOADED")) {
              isSendingJacsNotLoadedError = true;
            }
          }

          if (!isSendingJacsNotLoadedError) { 
             throw err;
          }
          // If it was an attempt to send a JACS_NOT_LOADED error, and signing that failed with JACS_NOT_LOADED,
          // then don't rethrow, to prevent an infinite loop.
      } else {
        console.error("Error in TransportMiddleware.send (NON-JACS related):", err.message, err.stack); // Added stack for other errors
        throw err; // Rethrow other errors
      }
    }
  }

  get sessionId(): string | undefined { return (this.transport as any).sessionId; }

  // handlePostMessage now takes an optional rawBodyString.
  // The HTTP server part (e.g., mcp.sse.server.js) is responsible for providing this.
  async handlePostMessage(req: IncomingMessage & { auth?: any }, res: ServerResponse, rawBodyString?: string): Promise<void> {
    let bodyToProcess: string;
    let potentialRequestId: string | number | null = null;

    if (rawBodyString !== undefined && typeof rawBodyString === 'string') {
        console.log("TransportMiddleware.handlePostMessage: Using provided rawBodyString.");
        bodyToProcess = rawBodyString;
    } else {
        console.warn("TransportMiddleware.handlePostMessage: rawBodyString not provided. Reading from request stream (ensure no prior JSON parsing middleware for this route).");
        const bodyBuffer = [];
        for await (const chunk of req) { bodyBuffer.push(chunk); }
        bodyToProcess = Buffer.concat(bodyBuffer).toString();
        if (!bodyToProcess) {
            console.error("TransportMiddleware.handlePostMessage: Fallback read from stream yielded empty body.");
            if (!res.writableEnded) res.writeHead(400).end("Empty request body.");
            return;
        }
    }

    console.log(`TransportMiddleware.handlePostMessage: Raw POST body for JACS (length ${bodyToProcess?.length}): ${bodyToProcess?.substring(0, 150)}...`);

    try {
        let messageForSDK: JSONRPCMessage;
        if (this.jacsOperational && this.incomingJacsTransformer) {
            console.log("TransportMiddleware.handlePostMessage: PRE-TRANSFORM. About to call incomingJacsTransformer. jacsOperational:", this.jacsOperational, "jacsLoaded:", jacsLoaded, "jacsLoadError:", jacsLoadError?.message);
            
            if (!jacsLoaded || jacsLoadError) {
                 const loadStateMsg = `JACS not ready (jacsLoaded: ${jacsLoaded}, jacsLoadError: ${jacsLoadError?.message}). Cannot apply JACS transform.`;
                 console.error("TransportMiddleware.handlePostMessage: " + loadStateMsg);
                 throw new Error(loadStateMsg); // Fail fast before calling transformer
            }
            
            messageForSDK = await this.incomingJacsTransformer(bodyToProcess);
            console.log("TransportMiddleware.handlePostMessage: POST-TRANSFORM. incomingJacsTransformer completed. Message for SDK:", JSON.stringify(messageForSDK).substring(0,100));

        } else {
            if (!this.jacsOperational) {
                console.log("TransportMiddleware.handlePostMessage: JACS not operational. Parsing as JSON directly.");
            } else { // jacsOperational is true, but no incomingJacsTransformer
                console.warn("TransportMiddleware.handlePostMessage: JACS is operational but no incomingJacsTransformer defined. Parsing as JSON directly.");
            }
            messageForSDK = JSON.parse(bodyToProcess) as JSONRPCMessage;
        }
        
        if (messageForSDK && 'id' in messageForSDK) {
            potentialRequestId = messageForSDK.id as string | number | null;
        }

        if (this.onmessage) {
            this.onmessage(messageForSDK); 
        } else {
            console.error("TransportMiddleware.handlePostMessage: No onmessage handler registered on middleware to pass the processed message.");
            if (!res.writableEnded) res.writeHead(500).end("Server misconfiguration: no message handler");
            return;
        }
        
        if (!res.writableEnded) {
            res.writeHead(202).end(); // Accepted
        }

    } catch (error) {
        const err = error as Error;
        // Log the specific error received from the transformer or JSON.parse
        console.error("TransportMiddleware.handlePostMessage: Error during message transformation or processing. Error message:", err.message);
        console.error("TransportMiddleware.handlePostMessage: Full error stack:", err.stack); // Log the full stack
        
        // Check if it's a JACS-specific known error type from our throws
        if (err.message.startsWith("Native jacs.verifyResponse failed:") || 
            err.message.startsWith("jacsVerifyTransform:") ||
            err.message.includes("JACS_NOT_LOADED")) {
            console.error("TransportMiddleware.handlePostMessage: JACS-specific error caught:", err.message);
        }

        if (this.onmessage) {
            const errorPayload: JSONRPCError["error"] = { code: ErrorCode.ParseError, message: `Failed to process POSTed JACS message: ${err.message}` };
            let errorResponse: JSONRPCError;
            const finalErrorId = potentialRequestId === undefined ? null : potentialRequestId;

            errorResponse = {
                jsonrpc: "2.0",
                id: finalErrorId, 
                error: errorPayload
            } as any;
        }

        if (!res.writableEnded) {
            res.writeHead(400).end(`Error processing request: ${err.message}`);
        }
        if (this.onerror) {
            this.onerror(err);
        }
    }
  }
}

export function createJacsMiddleware(
  transport: Transport, 
  configPath: string
): TransportMiddleware {
  console.log("Creating JACS Middleware: Using jacsSignTransform (obj->str) and jacsVerifyTransform (str->obj).");
  return new TransportMiddleware(
    transport,
    jacsSignTransform,
    async (jacsString: string): Promise<JSONRPCMessage> => {
        return jacsVerifyTransform(jacsString, 'incoming', 'unknown');
    },
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