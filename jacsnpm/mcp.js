"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJacsMiddleware = exports.TransportMiddleware = exports.jacsVerifyTransform = void 0;
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
// Renaming for clarity: this transforms an outgoing JSONRPCMessage to a JACS string
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
const jacsVerifyTransform = async (messageData, // Type is now string | object
jacs, enableDiagnosticLogging = false) => {
    const diagnosticPrefix = "jacsVerifyTransform: ";
    await ensureJacsLoaded(jacs, diagnosticPrefix);
    let jacsObjectInput;
    if (typeof messageData === 'string') {
        if (enableDiagnosticLogging) {
            console.log(`${diagnosticPrefix}Input is STRING (length ${messageData.length}). Parsing to JACS object... Content: ${messageData.substring(0, 300)}...`);
        }
        try {
            jacsObjectInput = JSON.parse(messageData);
        }
        catch (jsParseError) {
            const errorMsg = `${diagnosticPrefix}Input JACS string is invalid JSON.`;
            console.error(errorMsg, jsParseError.message, "Problematic JACS String:", messageData.substring(0, 500));
            throw new JacsError(errorMsg + ` Reason: ${jsParseError.message}`, "TRANSFORM_ERROR", { originalError: jsParseError });
        }
    }
    else if (typeof messageData === 'object' && messageData !== null) {
        if (enableDiagnosticLogging) {
            console.log(`${diagnosticPrefix}Input is OBJECT (already parsed JACS object).`);
        }
        jacsObjectInput = messageData;
    }
    else {
        const errorMsg = `${diagnosticPrefix}Input messageData is not a string or a valid object.`;
        console.error(errorMsg, messageData);
        throw new JacsError(errorMsg, "TRANSFORM_ERROR", { receivedData: messageData });
    }
    if (enableDiagnosticLogging) {
        try {
            const jacsObjectForLog = JSON.stringify(jacsObjectInput);
            console.log(`${diagnosticPrefix}JACS Object to be verified by native code (type ${typeof jacsObjectInput}): ${jacsObjectForLog.substring(0, 300)}...`);
        }
        catch (e) {
            console.log(`${diagnosticPrefix}Could not stringify jacsObjectInput for logging.`);
        }
    }
    // The NATIVE jacs.verifyResponse function expects a STRING (the full JACS document stringified)
    const jacsStringForNativeVerification = JSON.stringify(jacsObjectInput);
    if (enableDiagnosticLogging) {
        console.log(`${diagnosticPrefix}Stringified JACS Object being passed to NATIVE jacs.verifyResponse (length ${jacsStringForNativeVerification.length}): ${jacsStringForNativeVerification.substring(0, 300)}...`);
    }
    let verifiedPayloadString;
    try {
        verifiedPayloadString = await jacs.verifyResponse(jacsStringForNativeVerification); // Native call expects string
        if (enableDiagnosticLogging) {
            console.log(`${diagnosticPrefix}NATIVE jacs.verifyResponse SUCCEEDED.`);
        }
    }
    catch (nativeError) {
        const errorMsg = `${diagnosticPrefix}NATIVE jacs.verifyResponse FAILED.`;
        const jacsNotLoaded = nativeError.message?.includes("JACS_NOT_LOADED");
        const problemInputPreview = jacsStringForNativeVerification.substring(0, 500);
        console.error(errorMsg, jacsNotLoaded ? "(JACS_NOT_LOADED)" : nativeError.message, "Input JACS string to native function:", problemInputPreview);
        throw new JacsError(errorMsg + ` Reason: ${nativeError.message}`, jacsNotLoaded ? "JACS_NOT_LOADED" : "NATIVE_VERIFY_ERROR", { originalError: nativeError, inputToNative: problemInputPreview });
    }
    if (typeof verifiedPayloadString !== 'string') {
        const errorMsg = `${diagnosticPrefix}NATIVE jacs.verifyResponse did not return a string as expected.`;
        console.error(errorMsg, "Returned:", verifiedPayloadString);
        throw new JacsError(errorMsg, "NATIVE_VERIFY_ERROR", { returnValue: verifiedPayloadString });
    }
    if (enableDiagnosticLogging) {
        console.log(`${diagnosticPrefix}Payload string FROM jacs.verifyResponse (type string, length ${verifiedPayloadString.length}): ${verifiedPayloadString.substring(0, 300)}...`);
    }
    let finalMessageObject;
    try {
        finalMessageObject = JSON.parse(verifiedPayloadString);
    }
    catch (payloadParseError) {
        const errorMsg = `${diagnosticPrefix}Verified payload string is invalid JSON.`;
        console.error(errorMsg, payloadParseError.message, "Problematic Payload String:", verifiedPayloadString.substring(0, 500));
        throw new JacsError(errorMsg + ` Reason: ${payloadParseError.message}`, "PAYLOAD_PARSE_ERROR", { originalError: payloadParseError, payloadString: verifiedPayloadString.substring(0, 500) });
    }
    if (!isJSONRPCMessage(finalMessageObject)) {
        const errorMsg = `${diagnosticPrefix}Verified and parsed payload is not a valid JSONRPCMessage.`;
        console.error(errorMsg, finalMessageObject);
        throw new JacsError(errorMsg, "INVALID_PAYLOAD_STRUCTURE", { parsedPayload: finalMessageObject });
    }
    if (enableDiagnosticLogging) {
        console.log(`${diagnosticPrefix}Successfully transformed JACS to JSONRPCMessage:`, finalMessageObject);
    }
    return finalMessageObject;
};
exports.jacsVerifyTransform = jacsVerifyTransform;
class TransportMiddleware {
    constructor(transport, 
    // For outgoing messages: transform JSONRPCMessage to JACS string
    outgoingJacsTransformer, 
    // For incoming messages: transform JACS string to JSONRPCMessage
    incomingJacsTransformer, jacsConfigPath) {
        this.transport = transport;
        this.outgoingJacsTransformer = outgoingJacsTransformer;
        this.incomingJacsTransformer = incomingJacsTransformer;
        this.jacsConfigPath = jacsConfigPath;
        this.jacsOperational = true;
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
        }
        else {
            this.jacsOperational = false; // Explicitly false if no path
            console.warn("TransportMiddleware: No JACS config path provided. JACS will be NON-OPERATIONAL.");
        }
        this.transport.onmessage = async (messageDataFromTransport, // Can be string (server POST) or object (client SSE)
        extra) => {
            const middlewareType = this.isServerTransport(this.transport) ? "Server" : "Client";
            const diagnosticPrefix = `[${middlewareType} JACS Middleware OnMessageRecv] `;
            let messageForSDK = undefined;
            if (this.enableDiagnosticLogging) {
                console.log(`${diagnosticPrefix}Raw message from transport:`, messageDataFromTransport);
            }
            if (this.jacsOperational && this.incomingJacsTransformer) {
                if (this.enableDiagnosticLogging) {
                    console.log(`${diagnosticPrefix}JACS operational. Applying incomingJacsTransformer.`);
                }
                try {
                    // Pass messageDataFromTransport directly. jacsVerifyTransform handles string or object.
                    messageForSDK = await this.incomingJacsTransformer(messageDataFromTransport, this.jacs, this.enableDiagnosticLogging);
                }
                catch (e) {
                    const jacError = e instanceof JacsError ? e : new JacsError("Unknown transformation error", "TRANSFORM_ERROR", { originalError: e });
                    console.error(`${diagnosticPrefix}incomingJacsTransformer FAILED. Error: ${jacError.message}`, "Details:", jacError.details, "Original message:", messageDataFromTransport);
                    // If JACS fails to verify/transform, we should inform the McpEntity (client/server)
                    // by synthesizing a JSONRPCError response if possible, or re-throwing.
                    // For now, we'll create an error message to send to the SDK if it's a request context
                    // (i.e., if we can determine a request ID).
                    // If it's a response context (client receiving from server), the request might just time out.
                    // A robust solution would involve checking if messageDataFromTransport had an ID to construct a proper JSONRPCError.
                    // For simplicity here, if transformation fails, we won't call onmessageCallback.
                    // This specific error should ideally be converted to a JSONRPCError response by the MCP server if it's handling a request.
                    // If the client fails to decrypt a response, the original request will time out.
                    // Re-throw the error to be caught by the transport's error handling or global error handlers.
                    // Or, if onmessageCallback is defined, emit an error through it if the SDK supports that.
                    // For now, we just don't proceed. The original request will time out on the client.
                    return;
                }
            }
            else if (isJSONRPCMessage(messageDataFromTransport)) {
                if (this.enableDiagnosticLogging) {
                    console.log(`${diagnosticPrefix}JACS not operational or no transformer. Message is JSONRPC. Passing through.`);
                }
                messageForSDK = messageDataFromTransport;
            }
            else {
                console.error(`${diagnosticPrefix}JACS not operational/no transformer, and message is not JSONRPC. Discarding. Type: ${typeof messageDataFromTransport}`, messageDataFromTransport);
                return;
            }
            if (messageForSDK && this.onmessage) {
                if (this.enableDiagnosticLogging) {
                    console.log(`${diagnosticPrefix}Forwarding processed message to SDK's onmessageCallback:`, messageForSDK);
                }
                this.onmessage(messageForSDK, extra);
            }
            else if (!messageForSDK) {
                console.error(`${diagnosticPrefix}messageForSDK is undefined after processing. Cannot forward to SDK. Original data:`, messageDataFromTransport);
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
        let wasJacsTransformed = false; // Flag to know what was sent
        try {
            if (this.outgoingJacsTransformer && this.jacsOperational) {
                let skipJacsTransform = false;
                if ((0, types_js_1.isJSONRPCResponse)(messageForJacs) &&
                    'error' in messageForJacs &&
                    messageForJacs.error &&
                    typeof messageForJacs.error === 'object' &&
                    'message' in messageForJacs.error &&
                    typeof messageForJacs.error.message === 'string') {
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
            console.log(`[UNCONDITIONAL] TransportMiddleware.send: ABOUT TO SEND. Was JACS: ${wasJacsTransformed}, Len: ${payloadForTransport.length}, Payload: ${payloadForTransport.substring(0, 100)}...`);
            await this.transport.send(payloadForTransport);
            // UNCONDITIONAL LOG
            console.log(`[UNCONDITIONAL] TransportMiddleware.send: SUCCESSFULLY SENT.`);
        }
        catch (error) {
            const err = error;
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
            }
            else {
                console.error("Error in TransportMiddleware.send (NON-JACS related):", err.message, err.stack); // Added stack for other errors
                throw err; // Rethrow other errors
            }
        }
    }
    get sessionId() { return this.transport.sessionId; }
    // handlePostMessage now takes an optional rawBodyString.
    // The HTTP server part (e.g., mcp.sse.server.js) is responsible for providing this.
    async handlePostMessage(req, res, rawBodyString) {
        let bodyToProcess;
        let potentialRequestId = null;
        if (rawBodyString !== undefined && typeof rawBodyString === 'string') {
            console.log("TransportMiddleware.handlePostMessage: Using provided rawBodyString.");
            bodyToProcess = rawBodyString;
        }
        else {
            console.warn("TransportMiddleware.handlePostMessage: rawBodyString not provided. Reading from request stream (ensure no prior JSON parsing middleware for this route).");
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
        console.log(`TransportMiddleware.handlePostMessage: Raw POST body for JACS (length ${bodyToProcess?.length}): ${bodyToProcess?.substring(0, 150)}...`);
        try {
            let messageForSDK;
            if (this.jacsOperational && this.incomingJacsTransformer) {
                console.log("TransportMiddleware.handlePostMessage: PRE-TRANSFORM. About to call incomingJacsTransformer. jacsOperational:", this.jacsOperational, "jacsLoaded:", jacsLoaded, "jacsLoadError:", jacsLoadError?.message);
                if (!jacsLoaded || jacsLoadError) {
                    const loadStateMsg = `JACS not ready (jacsLoaded: ${jacsLoaded}, jacsLoadError: ${jacsLoadError?.message}). Cannot apply JACS transform.`;
                    console.error("TransportMiddleware.handlePostMessage: " + loadStateMsg);
                    throw new Error(loadStateMsg); // Fail fast before calling transformer
                }
                messageForSDK = await this.incomingJacsTransformer(bodyToProcess);
                console.log("TransportMiddleware.handlePostMessage: POST-TRANSFORM. incomingJacsTransformer completed. Message for SDK:", JSON.stringify(messageForSDK).substring(0, 100));
            }
            else {
                if (!this.jacsOperational) {
                    console.log("TransportMiddleware.handlePostMessage: JACS not operational. Parsing as JSON directly.");
                }
                else { // jacsOperational is true, but no incomingJacsTransformer
                    console.warn("TransportMiddleware.handlePostMessage: JACS is operational but no incomingJacsTransformer defined. Parsing as JSON directly.");
                }
                messageForSDK = JSON.parse(bodyToProcess);
            }
            if (messageForSDK && 'id' in messageForSDK) {
                potentialRequestId = messageForSDK.id;
            }
            if (this.onmessage) {
                this.onmessage(messageForSDK);
            }
            else {
                console.error("TransportMiddleware.handlePostMessage: No onmessage handler registered on middleware to pass the processed message.");
                if (!res.writableEnded)
                    res.writeHead(500).end("Server misconfiguration: no message handler");
                return;
            }
            if (!res.writableEnded) {
                res.writeHead(202).end(); // Accepted
            }
        }
        catch (error) {
            const err = error;
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
                const errorPayload = { code: types_js_1.ErrorCode.ParseError, message: `Failed to process POSTed JACS message: ${err.message}` };
                let errorResponse;
                const finalErrorId = potentialRequestId === undefined ? null : potentialRequestId;
                errorResponse = {
                    jsonrpc: "2.0",
                    id: finalErrorId,
                    error: errorPayload
                };
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
exports.TransportMiddleware = TransportMiddleware;
function createJacsMiddleware(transport, configPath) {
    console.log("Creating JACS Middleware: Using jacsSignTransform (obj->str) and jacsVerifyTransform (str->obj).");
    return new TransportMiddleware(transport, jacsSignTransform, async (jacsString) => {
        return (0, exports.jacsVerifyTransform)(jacsString, index_js_1.default, enableDiagnosticLogging);
    }, configPath);
}
exports.createJacsMiddleware = createJacsMiddleware;
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