"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJacsMiddlewareAsync = exports.createJacsMiddleware = exports.TransportMiddleware = void 0;
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const index_js_1 = __importDefault(require("./index.js")); // Assuming this has { signRequest: (data: any) => Promise<any>, verifyResponse: (data: any) => Promise<any> }
// Load JACS config only once
let jacsLoaded = false;
let jacsLoadError = null;
async function ensureJacsLoaded(configPath) {
    if (jacsLoaded)
        return; // If successfully loaded, nothing to do.
    if (jacsLoadError)
        throw jacsLoadError; // If previously failed, re-throw the known error.
    try {
        console.log(`ensureJacsLoaded: Attempting to load JACS config from: ${configPath}`);
        // Reset jacsLoadError before attempting to load
        jacsLoadError = null;
        await index_js_1.default.load(configPath);
        jacsLoaded = true;
        console.log(`ensureJacsLoaded: JACS agent loaded successfully from ${configPath}.`);
    }
    catch (error) {
        jacsLoadError = error;
        // Log the detailed error here immediately when it happens
        console.error(`ensureJacsLoaded: CRITICAL: Failed to load JACS config from '${configPath}'. Error:`, jacsLoadError.message, jacsLoadError.stack);
        throw jacsLoadError; // Re-throw to ensure the failure propagates
    }
}
const enableDiagnosticLogging = process.env.JACS_MCP_DEBUG === 'true';
// True whole-message JACS wrapping that completely hides JSON-RPC protocol
async function jacsSignTransform(message) {
    if (!jacsLoaded) {
        console.error("jacsSignTransform: JACS not loaded. Cannot sign.");
        throw new Error("JACS_NOT_LOADED_CANNOT_SIGN");
    }
    const original_message_id = ('id' in message && message.id !== null && typeof message.id !== 'undefined') ? message.id : undefined;
    try {
        if (enableDiagnosticLogging)
            console.log(`jacsSignTransform: Input TO jacs.signRequest (type ${typeof message}): ${JSON.stringify(message).substring(0, 100)}...`);
        // Sign the ENTIRE JSON-RPC message as the payload
        // This completely hides the JSON-RPC structure
        const jacs_artifact = await index_js_1.default.signRequest(message);
        if (enableDiagnosticLogging)
            console.log(`jacsSignTransform: Output FROM jacs.signRequest (type ${typeof jacs_artifact}, length ${typeof jacs_artifact === 'string' ? jacs_artifact.length : 'N/A'}): ${String(jacs_artifact).substring(0, 150)}...`);
        // Return the JACS artifact as-is (should be a string)
        // This completely replaces the JSON-RPC message with a JACS-signed blob
        const result = typeof jacs_artifact === 'string' ? jacs_artifact : JSON.stringify(jacs_artifact);
        if (enableDiagnosticLogging)
            console.log(`jacsSignTransform: SUCCESSFULLY SIGNED. Returning JACS string of length ${result.length}`);
        return result;
    }
    catch (error) {
        console.error(`jacsSignTransform: JACS signing failed (ID: ${original_message_id}). Error:`, error);
        throw error;
    }
}
async function jacsVerifyTransform(jacsArtifactString) {
    if (!jacsLoaded) {
        console.error("jacsVerifyTransform: JACS not loaded. Cannot verify.");
        throw new Error("JACS_NOT_LOADED_CANNOT_VERIFY");
    }
    try {
        if (enableDiagnosticLogging)
            console.log(`jacsVerifyTransform: Input TO jacs.verifyResponse (type ${typeof jacsArtifactString}, length ${jacsArtifactString.length}): ${jacsArtifactString.substring(0, 150)}...`);
        // Verify the JACS artifact string and get back the original JSON-RPC message
        const verificationResult = await index_js_1.default.verifyResponse(jacsArtifactString);
        if (enableDiagnosticLogging)
            console.log(`jacsVerifyTransform: Output FROM jacs.verifyResponse (type ${typeof verificationResult}): ${JSON.stringify(verificationResult).substring(0, 100)}...`);
        // Extract the original message from the verification result
        let originalMessage;
        if (verificationResult && typeof verificationResult === 'object') {
            // Check if verifyResponse returns an object with a payload property
            if ('payload' in verificationResult) {
                originalMessage = verificationResult.payload;
                if (enableDiagnosticLogging)
                    console.log(`jacsVerifyTransform: Extracted payload from verificationResult.payload`);
            }
            else {
                // If verifyResponse returns the payload directly
                originalMessage = verificationResult;
                if (enableDiagnosticLogging)
                    console.log(`jacsVerifyTransform: Using verificationResult directly as originalMessage`);
            }
        }
        else {
            console.error(`jacsVerifyTransform: JACS verification returned invalid data (type: ${typeof verificationResult}):`, verificationResult);
            throw new Error("JACS verification failed to return valid object.");
        }
        // Validate that we got back a proper JSON-RPC message
        if (!originalMessage || typeof originalMessage !== 'object' || originalMessage.jsonrpc !== '2.0') {
            console.error(`jacsVerifyTransform: Verified payload is not a valid JSON-RPC message. Got (type: ${typeof originalMessage}):`, originalMessage);
            throw new Error("JACS verification did not return a valid JSON-RPC message.");
        }
        if (enableDiagnosticLogging)
            console.log(`jacsVerifyTransform: SUCCESSFULLY VERIFIED. Returning original JSON-RPC message: ${JSON.stringify(originalMessage).substring(0, 200)}...`);
        return originalMessage;
    }
    catch (error) {
        console.error(`jacsVerifyTransform: JACS verification failed. Input was: ${jacsArtifactString.substring(0, 100)}... Error:`, error);
        throw error;
    }
}
// Updated TransportMiddleware for complete JACS wrapping
class TransportMiddleware {
    constructor(transport, role, outgoingJacsTransformer, incomingJacsTransformer, jacsConfigPath) {
        this.transport = transport;
        this.outgoingJacsTransformer = outgoingJacsTransformer;
        this.incomingJacsTransformer = incomingJacsTransformer;
        this.jacsConfigPath = jacsConfigPath;
        this.jacsOperational = true;
        this.middlewareId = role === "client" ? "CLIENT_MIDDLEWARE" : "SERVER_MIDDLEWARE";
        console.log(`[${this.middlewareId}] CONSTRUCTOR: Role: ${role}. JACS Config: ${jacsConfigPath}`);
        if (jacsConfigPath) {
            ensureJacsLoaded(jacsConfigPath)
                .then(() => { this.jacsOperational = true; console.log(`[${this.middlewareId}] JACS Loaded.`); })
                .catch(err => { this.jacsOperational = false; console.error(`[${this.middlewareId}] JACS Load FAILED:`, err.message); });
        }
        else {
            this.jacsOperational = false;
            console.warn(`[${this.middlewareId}] No JACS config. JACS Non-Operational.`);
        }
        this.transport.onmessage = async (messageOrStringFromTransport) => {
            const startLogPrefix = `[${this.middlewareId}] ONMESSAGE_HANDLER (transport.onmessage)`;
            if (enableDiagnosticLogging)
                console.log(`${startLogPrefix}: Received raw from transport. Type: ${typeof messageOrStringFromTransport}, Content: ${String(messageOrStringFromTransport).substring(0, 100)}...`);
            let messageObject;
            try {
                if (typeof messageOrStringFromTransport === 'string') {
                    // String payload - should be JACS-wrapped if JACS is operational
                    if (this.incomingJacsTransformer && this.jacsOperational) {
                        if (enableDiagnosticLogging)
                            console.log(`${startLogPrefix}: JACS operational, applying incomingJacsTransformer (string->obj).`);
                        messageObject = await this.incomingJacsTransformer(messageOrStringFromTransport);
                        if (enableDiagnosticLogging)
                            console.log(`${startLogPrefix}: incomingJacsTransformer completed successfully.`);
                    }
                    else {
                        // No JACS or not operational, parse as JSON
                        if (enableDiagnosticLogging)
                            console.log(`${startLogPrefix}: JACS not operational, parsing string as JSON.`);
                        messageObject = JSON.parse(messageOrStringFromTransport);
                    }
                }
                else if (typeof messageOrStringFromTransport === 'object' && messageOrStringFromTransport !== null && 'jsonrpc' in messageOrStringFromTransport) {
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix}: Received object, using as-is.`);
                    messageObject = messageOrStringFromTransport;
                }
                else {
                    console.error(`${startLogPrefix}: Received unexpected data type from transport:`, typeof messageOrStringFromTransport, messageOrStringFromTransport);
                    throw new Error("Invalid data type from transport");
                }
                if (enableDiagnosticLogging)
                    console.log(`${startLogPrefix}: Final message object prepared: ${JSON.stringify(messageObject).substring(0, 100)}...`);
                if (this.onmessage) {
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix}: Passing processed message to SDK's onmessage.`);
                    this.onmessage(messageObject);
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix}: SDK's onmessage returned successfully.`);
                }
                else {
                    console.error(`${startLogPrefix}: CRITICAL - No SDK onmessage handler!`);
                }
            }
            catch (error) {
                const err = error;
                console.error(`${startLogPrefix}: Error processing message. Err: ${err.message}`, err.stack);
                if (this.onerror)
                    this.onerror(err);
            }
        };
        this.transport.onclose = () => {
            console.log(`[${this.middlewareId}] Transport closed.`);
            if (this.onclose)
                this.onclose();
        };
        this.transport.onerror = (error) => {
            console.error(`[${this.middlewareId}] Transport error:`, error);
            if (this.onerror)
                this.onerror(error);
        };
        console.log(`[${this.middlewareId}] CONSTRUCTOR: Attached transport events.`);
    }
    async start() {
        console.log(`[${this.middlewareId}] Starting transport...`);
        return this.transport.start();
    }
    async close() {
        console.log(`[${this.middlewareId}] Closing transport...`);
        return this.transport.close();
    }
    async send(message) {
        const startLogPrefix = `[${this.middlewareId}] SEND`;
        if (enableDiagnosticLogging)
            console.log(`${startLogPrefix}: ABOUT TO SEND. Original msg (ID: ${'id' in message ? message.id : 'N/A'}): ${JSON.stringify(message).substring(0, 100)}...`);
        try {
            let payloadToSend = message;
            if (this.outgoingJacsTransformer && this.jacsOperational) {
                if ((0, types_js_1.isJSONRPCResponse)(message) && 'error' in message) {
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix}: Error response detected. Bypassing JACS transform.`);
                    // For error responses, still send as JSON since they may not need JACS protection
                    payloadToSend = message;
                }
                else {
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix}: JACS operational, applying outgoingJacsTransformer (obj->string).`);
                    payloadToSend = await this.outgoingJacsTransformer(message);
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix}: outgoingJacsTransformer completed. Result type: ${typeof payloadToSend}, length: ${typeof payloadToSend === 'string' ? payloadToSend.length : 'N/A'}`);
                }
            }
            else {
                if (enableDiagnosticLogging)
                    console.log(`${startLogPrefix}: JACS not operational, sending original message object.`);
            }
            const endpointProperty = message.endpoint;
            if (this.middlewareId === "SERVER_MIDDLEWARE" && typeof endpointProperty === 'string') {
                if (enableDiagnosticLogging)
                    console.log(`${startLogPrefix} (SSE Server): Detected 'endpoint' event. Value: ${endpointProperty}`);
                // Ensure _sseResponse is available and a ServerResponse (or similar with .write)
                const sseTransport = this.transport;
                if (sseTransport._sseResponse && typeof sseTransport._sseResponse.write === 'function') {
                    sseTransport._sseResponse.write(`event: endpoint\ndata: ${endpointProperty}\n\n`);
                    if (enableDiagnosticLogging)
                        console.log(`${startLogPrefix} (SSE Server): 'endpoint' event sent.`);
                }
                else {
                    console.warn(`${startLogPrefix} (SSE Server): _sseResponse not available or no write method for sending 'endpoint' event.`);
                }
                return;
            }
            // Send to underlying transport
            if (enableDiagnosticLogging)
                console.log(`${startLogPrefix}: Calling underlying transport.send() with payload type: ${typeof payloadToSend}`);
            await this.transport.send(payloadToSend);
            if (enableDiagnosticLogging)
                console.log(`${startLogPrefix}: SUCCESSFULLY SENT.`);
        }
        catch (error) {
            const err = error;
            console.error(`${startLogPrefix}: CAUGHT ERROR: ${err.message}`, err.stack);
            throw err;
        }
    }
    get sessionId() { return this.transport.sessionId; }
    async handlePostMessage(req, res, rawBodyString) {
        const logPrefix = `[${this.middlewareId} HTTP_POST_HANDLER]`;
        let bodyToProcess;
        if (rawBodyString !== undefined && typeof rawBodyString === 'string') {
            bodyToProcess = rawBodyString;
        }
        else {
            const bodyBuffer = [];
            for await (const chunk of req) {
                bodyBuffer.push(chunk);
            }
            bodyToProcess = Buffer.concat(bodyBuffer).toString();
            if (!bodyToProcess) {
                if (!res.writableEnded)
                    res.writeHead(400).end("Empty body.");
                return;
            }
        }
        if (enableDiagnosticLogging)
            console.log(`${logPrefix}: Raw POST body (len ${bodyToProcess?.length}): ${bodyToProcess?.substring(0, 100)}...`);
        try {
            let messageForSDK;
            if (this.jacsOperational && this.incomingJacsTransformer) {
                if (enableDiagnosticLogging)
                    console.log(`${logPrefix}: JACS operational. Calling incomingJacsTransformer (string->obj).`);
                messageForSDK = await this.incomingJacsTransformer(bodyToProcess);
                if (enableDiagnosticLogging)
                    console.log(`${logPrefix}: incomingJacsTransformer completed successfully.`);
            }
            else {
                if (enableDiagnosticLogging)
                    console.log(`${logPrefix}: JACS not operational. Parsing POST body as JSON.`);
                messageForSDK = JSON.parse(bodyToProcess);
            }
            if (this.onmessage) {
                if (enableDiagnosticLogging)
                    console.log(`${logPrefix}: Passing message to SDK's onmessage handler.`);
                this.onmessage(messageForSDK);
                if (enableDiagnosticLogging)
                    console.log(`${logPrefix}: SDK's onmessage handler completed.`);
            }
            else {
                console.error(`${logPrefix}: CRITICAL - No onmessage handler for POST.`);
                if (!res.writableEnded)
                    res.writeHead(500).end("Server error: no handler");
                return;
            }
            if (!res.writableEnded)
                res.writeHead(202).end();
            if (enableDiagnosticLogging)
                console.log(`${logPrefix}: POST request processing completed successfully.`);
        }
        catch (error) {
            const err = error;
            console.error(`${logPrefix}: Error in POST processing. Err: ${err.message}`, err.stack);
            if (!res.writableEnded)
                res.writeHead(400).end(`Err: ${err.message}`);
            if (this.onerror)
                this.onerror(err);
        }
    }
}
exports.TransportMiddleware = TransportMiddleware;
function createJacsMiddleware(transport, configPath, role) {
    console.log(`Creating JACS Middleware (sync init) for role: ${role} with complete message wrapping.`);
    return new TransportMiddleware(transport, role, jacsSignTransform, jacsVerifyTransform, configPath);
}
exports.createJacsMiddleware = createJacsMiddleware;
async function createJacsMiddlewareAsync(transport, configPath, role) {
    console.log(`Creating JACS Middleware (async init) for role: ${role}. Ensuring JACS loaded first.`);
    await ensureJacsLoaded(configPath);
    return new TransportMiddleware(transport, role, jacsSignTransform, jacsVerifyTransform, configPath);
}
exports.createJacsMiddlewareAsync = createJacsMiddlewareAsync;
//# sourceMappingURL=mcp.js.map