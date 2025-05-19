"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJacsMiddlewareAsync = exports.createJacsMiddleware = exports.TransportMiddleware = void 0;
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const index_js_1 = __importDefault(require("./index.js"));
// Load JACS config only once
let jacsLoaded = false;
let jacsLoadError = null;
async function ensureJacsLoaded(configPath) {
    if (jacsLoaded)
        return; // If successfully loaded, nothing to do.
    if (jacsLoadError)
        throw jacsLoadError; // If previously failed, re-throw the known error.
    try {
        console.log(`Attempting to load JACS config from: ${configPath}`);
        // Reset jacsLoadError before attempting to load
        jacsLoadError = null;
        await index_js_1.default.load(configPath);
        jacsLoaded = true;
        console.log("JACS agent loaded successfully.");
    }
    catch (error) {
        jacsLoadError = error;
        // Log the detailed error here immediately when it happens
        console.error(`CRITICAL: Failed to load JACS configuration from '${configPath}'. Error:`, jacsLoadError.message, jacsLoadError.stack);
        throw jacsLoadError; // Re-throw to ensure the failure propagates
    }
}
async function jacsSignTransform(message) {
    if (!jacsLoaded) {
        console.error("jacsSignTransform: JACS not loaded. Cannot sign.");
        throw new Error("JACS_NOT_LOADED_CANNOT_SIGN");
    }
    try {
        console.log(`jacsSignTransform: Input TO jacs.signRequest (type ${typeof message}): ${JSON.stringify(message).substring(0, 200)}...`);
        const signedJacsString = await index_js_1.default.signRequest(message);
        console.log(`jacsSignTransform: Output FROM jacs.signRequest (type ${typeof signedJacsString}, length ${signedJacsString?.length}): ${signedJacsString?.substring(0, 200)}...`);
        if (typeof signedJacsString !== 'string') {
            console.error("CRITICAL: jacs.signRequest did NOT return a string!");
            throw new Error("jacs.signRequest did not return a string");
        }
        return signedJacsString;
    }
    catch (error) {
        console.error("jacsSignTransform: JACS signing failed. Input was (approx):", JSON.stringify(message).substring(0, 200), "Error:", error);
        throw error;
    }
}
const enableDiagnosticLogging = process.env.JACS_MCP_DEBUG === 'true';
// JACS Verification Transformer (string-to-object, or object-to-object if already parsed)
// This transformer takes a JACS string (or an already parsed JACS object),
// verifies it using the native jacs.verifyResponse, and returns the inner JSONRPCMessage.
async function jacsVerifyTransform(jacsInput, // Can be a JACS string or an already parsed JACS object
direction, // for logging/context
messageType) {
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
    let jacsObject; // This will be the JACS header object
    let verifiedPayloadObject; // This will hold the final JSONRPC message payload
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
        }
        catch (jsParseError) {
            const errorMsg = `jacsVerifyTransform: Input JACS string is invalid JSON. Error: ${jsParseError.message}. Input (first 200 chars): ${jacsInput.substring(0, 200)}`;
            console.error(errorMsg);
            throw new Error(errorMsg);
        }
    }
    else if (typeof jacsInput === 'object' && jacsInput !== null) {
        jacsObject = jacsInput; // Input is already the JACS header object
        if (enableDiagnosticLogging) {
            console.log(`jacsVerifyTransform: Received object input (assumed to be JACS header object).`);
        }
    }
    else {
        const errorMsg = `jacsVerifyTransform: Invalid input type. Expected JACS string or JACS header object, got ${typeof jacsInput}.`;
        console.error(errorMsg, jacsInput);
        throw new Error(errorMsg);
    }
    let rawVerifiedOutput;
    if (enableDiagnosticLogging) {
        console.log(`jacsVerifyTransform: JACS Header Object Input TO NATIVE jacs.verifyResponse (type object):`, JSON.stringify(jacsObject)?.substring(0, 300));
    }
    try {
        rawVerifiedOutput = await index_js_1.default.verifyResponse(jacsObject);
        if (enableDiagnosticLogging) {
            console.log(`jacsVerifyTransform: NATIVE jacs.verifyResponse SUCCEEDED. Returned raw output type: ${typeof rawVerifiedOutput}`, JSON.stringify(rawVerifiedOutput)?.substring(0, 300));
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
        }
        else {
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
    }
    catch (nativeError) {
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
    return verifiedPayloadObject;
}
class TransportMiddleware {
    constructor(transport, 
    // For outgoing messages: transform JSONRPCMessage to JACS string
    outgoingJacsTransformer, 
    // For incoming messages: jacsInput can be JACS string (e.g. server POST) OR pre-parsed JACS object (e.g. client SSE)
    incomingJacsTransformer, jacsConfigPath) {
        this.transport = transport;
        this.outgoingJacsTransformer = outgoingJacsTransformer;
        this.incomingJacsTransformer = incomingJacsTransformer;
        this.jacsConfigPath = jacsConfigPath;
        this.jacsOperational = true;
        if (jacsConfigPath) {
            ensureJacsLoaded(jacsConfigPath)
                .then(() => {
                this.jacsOperational = true;
                console.log("TransportMiddleware: JACS loaded successfully via constructor call.");
            })
                .catch(err => {
                this.jacsOperational = false;
                console.error("TransportMiddleware Constructor: ensureJacsLoaded FAILED, JACS will be NON-OPERATIONAL. Error:", err.message);
            });
        }
        else {
            this.jacsOperational = false;
            console.warn("TransportMiddleware: No JACS config path provided. JACS will be NON-OPERATIONAL.");
        }
        this.transport.onmessage = async (messageOrObjectFromTransport) => {
            let requestId = null;
            try {
                console.log(`TransportMiddleware.onmessage: Raw incoming data type: ${typeof messageOrObjectFromTransport}`);
                if (enableDiagnosticLogging) {
                    console.log(`TransportMiddleware.onmessage: Data sample: ${typeof messageOrObjectFromTransport === 'string' ? messageOrObjectFromTransport.substring(0, 150) : JSON.stringify(messageOrObjectFromTransport)?.substring(0, 150)}...`);
                }
                let processedMessage;
                if (this.incomingJacsTransformer && this.jacsOperational) {
                    console.log("TransportMiddleware.onmessage: JACS operational, applying incomingJacsTransformer.");
                    processedMessage = await this.incomingJacsTransformer(messageOrObjectFromTransport, 'incoming', 'unknown');
                }
                else {
                    if (typeof messageOrObjectFromTransport === 'string') {
                        console.log("TransportMiddleware.onmessage: No JACS (or not operational). Parsing string as JSONRPCMessage.");
                        processedMessage = JSON.parse(messageOrObjectFromTransport);
                    }
                    else if (typeof messageOrObjectFromTransport === 'object' && messageOrObjectFromTransport !== null) {
                        if (!('jsonrpc' in messageOrObjectFromTransport && messageOrObjectFromTransport.jsonrpc === '2.0') && enableDiagnosticLogging) {
                            console.warn("TransportMiddleware.onmessage: Received object that doesn't look like JSONRPC, but JACS not operational. Passing as is.");
                        }
                        processedMessage = messageOrObjectFromTransport;
                    }
                    else {
                        throw new Error(`Unexpected message type: ${typeof messageOrObjectFromTransport}`);
                    }
                }
                if (processedMessage && 'id' in processedMessage) {
                    requestId = processedMessage.id;
                }
                if (this.onmessage) {
                    console.log(`TransportMiddleware.onmessage: Passing processed message to SDK: ${JSON.stringify(processedMessage).substring(0, 100)}...`);
                    this.onmessage(processedMessage);
                }
            }
            catch (error) {
                const err = error;
                console.error("Error in TransportMiddleware.onmessage processing:", err.message, err.stack);
                const errorPayload = { code: types_js_1.ErrorCode.InternalError, message: `Middleware onmessage error: ${err.message}` };
                let errorResponse;
                const finalErrorId = requestId === null || requestId === undefined ? undefined : requestId;
                if (finalErrorId !== undefined) {
                    errorResponse = {
                        jsonrpc: "2.0",
                        id: finalErrorId,
                        error: errorPayload
                    };
                }
                else {
                    errorResponse = {
                        jsonrpc: "2.0",
                        id: null,
                        error: errorPayload
                    };
                }
                if (finalErrorId !== undefined && finalErrorId !== null) {
                    try {
                        console.warn(`TransportMiddleware.onmessage: Attempting to send error response for request ID ${finalErrorId}:`, errorResponse);
                        await this.send(errorResponse);
                    }
                    catch (sendError) {
                        console.error("TransportMiddleware.onmessage: CRITICAL - Failed to send error response via this.send:", sendError);
                    }
                }
                else {
                    console.warn("TransportMiddleware.onmessage: Error occurred, but no request ID available or it's a notification. Not sending JSONRPC error upstream.", errorResponse);
                }
                if (this.onerror) {
                    this.onerror(err);
                }
            }
        };
        this.transport.onclose = () => { if (this.onclose)
            this.onclose(); };
        this.transport.onerror = (error) => { if (this.onerror)
            this.onerror(error); };
    }
    async start() { return this.transport.start(); }
    async close() { return this.transport.close(); }
    async send(message) {
        let messageForJacs = message;
        let transformedMessageString = null;
        let wasJacsTransformed = false;
        try {
            if (this.outgoingJacsTransformer && this.jacsOperational) {
                let skipJacsTransform = false;
                if ((0, types_js_1.isJSONRPCResponse)(messageForJacs) &&
                    'error' in messageForJacs &&
                    messageForJacs.error && // Ensures error object exists
                    typeof messageForJacs.error.message === 'string' // Check if error.message is a string
                ) {
                    // Now it's safer to access messageForJacs.error.message
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
            // The payload for transport contains the JACS-transformed message or the original JSON-RPC message
            const payloadForTransport = transformedMessageString ?? JSON.stringify(messageForJacs);
            console.log(`[UNCONDITIONAL] TransportMiddleware.send: ABOUT TO SEND. 
        Was JACS: ${wasJacsTransformed}, Len: ${payloadForTransport.length}, Payload: ${payloadForTransport}...`);
            // Check if the underlying transport is an SSE transport
            if (typeof this.transport._sseResponse !== 'undefined') {
                // This is an SSE transport - we need to format the message in SSE format
                const sseResponse = this.transport._sseResponse;
                if (!sseResponse) {
                    throw new Error("SSE connection not established");
                }
                // Send the message using SSE event format
                sseResponse.write(`event: message\ndata: ${payloadForTransport}\n\n`);
                console.log(`[UNCONDITIONAL] TransportMiddleware.send: SENT AS SSE EVENT.`);
            }
            else {
                // Standard transport, use the normal send method
                await this.transport.send(payloadForTransport);
            }
            console.log(`[UNCONDITIONAL] TransportMiddleware.send: SUCCESSFULLY SENT.`);
        }
        catch (error) {
            const err = error;
            console.error("[UNCONDITIONAL] TransportMiddleware.send: CAUGHT ERROR:", err.message, err.stack);
            let isTryingToSendJacsNotLoadedError = false;
            if ((0, types_js_1.isJSONRPCResponse)(message) &&
                'error' in message &&
                message.error && // Ensures error object exists
                typeof message.error.message === 'string' // Check if error.message is a string
            ) {
                // Now it's safer to access message.error.message
                if (message.error.message.includes("JACS_NOT_LOADED")) {
                    isTryingToSendJacsNotLoadedError = true;
                }
            }
            if (err.message?.includes("JACS_NOT_LOADED") && isTryingToSendJacsNotLoadedError) {
                console.error("TransportMiddleware.send: Failed to sign a JACS_NOT_LOADED error (likely because JACS is still not loaded). Suppressing further error to prevent loop.");
            }
            else {
                throw err;
            }
        }
    }
    get sessionId() { return this.transport.sessionId; }
    async handlePostMessage(req, res, rawBodyString) {
        let bodyToProcess;
        let potentialRequestId = null;
        if (rawBodyString !== undefined && typeof rawBodyString === 'string') {
            console.log("TransportMiddleware.handlePostMessage: Using provided rawBodyString.");
            bodyToProcess = rawBodyString;
        }
        else {
            console.warn("TransportMiddleware.handlePostMessage: rawBodyString not provided by HTTP server. Attempting to read from request stream.");
            const bodyBuffer = [];
            for await (const chunk of req) {
                bodyBuffer.push(chunk);
            }
            bodyToProcess = Buffer.concat(bodyBuffer).toString();
            if (!bodyToProcess) {
                console.error("TransportMiddleware.handlePostMessage: Fallback read from stream yielded empty body.");
                if (!res.writableEnded)
                    res.writeHead(400).end("Empty request body.");
                return;
            }
        }
        if (enableDiagnosticLogging) {
            console.log(`TransportMiddleware.handlePostMessage: Raw POST body (length ${bodyToProcess?.length}): ${bodyToProcess?.substring(0, 150)}...`);
        }
        try {
            let messageForSDK;
            if (this.jacsOperational && this.incomingJacsTransformer) {
                console.log("TransportMiddleware.handlePostMessage: PRE-TRANSFORM. About to call incomingJacsTransformer with POST body. jacsOperational:", this.jacsOperational, "jacsLoaded:", jacsLoaded);
                if (!jacsLoaded || jacsLoadError) {
                    const loadStateMsg = `JACS not ready in handlePostMessage (jacsLoaded: ${jacsLoaded}, jacsLoadError: ${jacsLoadError?.message}). Cannot apply JACS transform.`;
                    console.error(loadStateMsg);
                    throw new Error(loadStateMsg);
                }
                messageForSDK = await this.incomingJacsTransformer(bodyToProcess, 'incoming', 'unknown');
                console.log("TransportMiddleware.handlePostMessage: POST-TRANSFORM. incomingJacsTransformer completed. Message for SDK:", JSON.stringify(messageForSDK).substring(0, 100));
            }
            else {
                console.log("TransportMiddleware.handlePostMessage: JACS not operational or no transformer. Parsing POST body as JSON directly.");
                messageForSDK = JSON.parse(bodyToProcess);
            }
            if (messageForSDK && 'id' in messageForSDK) {
                potentialRequestId = messageForSDK.id;
            }
            if (this.onmessage) {
                this.onmessage(messageForSDK);
            }
            else {
                console.error("TransportMiddleware.handlePostMessage: CRITICAL - No onmessage handler registered on middleware to pass the processed message from POST.");
                if (!res.writableEnded)
                    res.writeHead(500).end("Server error: no message handler for POSTed data");
                return;
            }
            if (!res.writableEnded) {
                res.writeHead(202).end();
            }
        }
        catch (error) {
            const err = error;
            console.error("TransportMiddleware.handlePostMessage: Error during POST message transformation or processing. Error message:", err.message, "\nFull error stack:", err.stack);
            if (!res.writableEnded) {
                res.writeHead(400).end(`Error processing request: ${err.message}`);
            }
            if (this.onerror) {
                this.onerror(err);
            }
        }
    }
}
exports.TransportMiddleware = TransportMiddleware;
function createJacsMiddleware(transport, configPath) {
    console.log("Creating JACS Middleware: Using jacsSignTransform (obj->JACS_str) and jacsVerifyTransform (JACS_str_or_obj->obj).");
    return new TransportMiddleware(transport, jacsSignTransform, jacsVerifyTransform, configPath);
}
exports.createJacsMiddleware = createJacsMiddleware;
async function createJacsMiddlewareAsync(transport, configPath) {
    await ensureJacsLoaded(configPath);
    return new TransportMiddleware(transport, jacsSignTransform, jacsVerifyTransform, configPath);
}
exports.createJacsMiddlewareAsync = createJacsMiddlewareAsync;
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
//# sourceMappingURL=mcp.js.map