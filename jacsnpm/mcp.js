"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createJACSTransportProxyAsync = exports.createJACSTransportProxy = exports.JACSTransportProxy = void 0;
const index_js_1 = __importDefault(require("./index.js"));
// Add near the top, after imports:
const isStdioTransport = (transport) => {
    return transport.constructor.name === 'StdioServerTransport' ||
        transport.constructor.name === 'StdioClientTransport';
};
let enableDiagnosticLogging = false;
function jacslog(...args) {
    console.error(...args);
}
// Load JACS config only once
let jacsLoaded = false;
let jacsLoadError = null;
async function ensureJacsLoaded(configPath) {
    if (jacsLoaded)
        return;
    if (jacsLoadError)
        throw jacsLoadError;
    try {
        jacslog(`ensureJacsLoaded: Attempting to load JACS config from: ${configPath}`);
        jacsLoadError = null;
        await index_js_1.default.load(configPath);
        jacsLoaded = true;
        jacslog(`ensureJacsLoaded: JACS agent loaded successfully from ${configPath}.`);
    }
    catch (error) {
        jacsLoadError = error;
        console.error(`ensureJacsLoaded: CRITICAL: Failed to load JACS config from '${configPath}'. Error:`, jacsLoadError.message);
        throw jacsLoadError;
    }
}
/**
 * JACS Transport Proxy - Wraps any transport with JACS encryption
 *
 * This proxy sits between the MCP SDK and the actual transport,
 * intercepting serialized JSON strings (not JSON-RPC objects)
 */
class JACSTransportProxy {
    constructor(transport, role, jacsConfigPath) {
        this.transport = transport;
        this.jacsConfigPath = jacsConfigPath;
        this.jacsOperational = true;
        this.proxyId = `JACS_${role.toUpperCase()}_PROXY`;
        // Disable JACS debugging for STDIO transports to prevent stdout contamination
        const suppressDebugForStdio = isStdioTransport(transport);
        const enableDiagnosticLogging = process.env.JACS_MCP_DEBUG === 'true' && !suppressDebugForStdio;
        if (suppressDebugForStdio) {
            console.error(`[${this.proxyId}] STDIO transport detected, suppressing debug output`);
        }
        jacslog(`[${this.proxyId}] CONSTRUCTOR: Wrapping transport with JACS. Config: ${jacsConfigPath}`);
        if (jacsConfigPath) {
            ensureJacsLoaded(jacsConfigPath)
                .then(() => {
                this.jacsOperational = true;
                jacslog(`[${this.proxyId}] JACS Loaded and operational.`);
            })
                .catch(err => {
                this.jacsOperational = false;
                console.error(`[${this.proxyId}] JACS Load FAILED:`, err.message);
            });
        }
        else {
            this.jacsOperational = false;
            console.warn(`[${this.proxyId}] No JACS config provided. Operating in passthrough mode.`);
        }
        // Intercept incoming messages from the transport
        this.transport.onmessage = async (incomingData) => {
            const logPrefix = `[${this.proxyId}] INCOMING`;
            try {
                let messageForSDK;
                if (typeof incomingData === 'string') {
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: Received string from transport (len ${incomingData.length}): ${incomingData.substring(0, 100)}...`);
                    if (this.jacsOperational) {
                        // Try to decrypt/verify the string as a JACS artifact
                        try {
                            if (enableDiagnosticLogging)
                                jacslog(`${logPrefix}: Attempting JACS verification of string...`);
                            const verificationResult = await index_js_1.default.verifyResponse(incomingData);
                            let decryptedMessage;
                            if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
                                decryptedMessage = verificationResult.payload;
                            }
                            else {
                                decryptedMessage = verificationResult;
                            }
                            if (enableDiagnosticLogging)
                                jacslog(`${logPrefix}: JACS verification successful. Decrypted message: ${JSON.stringify(decryptedMessage).substring(0, 100)}...`);
                            messageForSDK = decryptedMessage;
                        }
                        catch (jacsError) {
                            // Not a JACS artifact, treat as plain JSON
                            const errorMessage = jacsError instanceof Error ? jacsError.message : "Unknown JACS error";
                            if (enableDiagnosticLogging)
                                jacslog(`${logPrefix}: Not a JACS artifact, parsing as plain JSON. JACS error was: ${errorMessage}`);
                            messageForSDK = JSON.parse(incomingData);
                        }
                    }
                    else {
                        // JACS not operational, parse as plain JSON
                        if (enableDiagnosticLogging)
                            jacslog(`${logPrefix}: JACS not operational, parsing as plain JSON.`);
                        messageForSDK = JSON.parse(incomingData);
                    }
                }
                else if (typeof incomingData === 'object' && incomingData !== null && 'jsonrpc' in incomingData) {
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: Received object from transport, using as-is.`);
                    messageForSDK = incomingData;
                }
                else {
                    console.error(`${logPrefix}: Unexpected data type from transport:`, typeof incomingData);
                    throw new Error("Invalid data type from transport");
                }
                if (enableDiagnosticLogging)
                    jacslog(`${logPrefix}: Passing to MCP SDK: ${JSON.stringify(messageForSDK).substring(0, 100)}...`);
                // Pass the clean JSON-RPC message to the MCP SDK
                if (this.onmessage) {
                    this.onmessage(messageForSDK);
                }
            }
            catch (error) {
                console.error(`${logPrefix}: Error processing incoming message:`, error);
                if (this.onerror)
                    this.onerror(error);
            }
        };
        // Forward transport events
        this.transport.onclose = () => {
            jacslog(`[${this.proxyId}] Transport closed.`);
            if (this.onclose)
                this.onclose();
        };
        this.transport.onerror = (error) => {
            console.error(`[${this.proxyId}] Transport error:`, error);
            if (this.onerror)
                this.onerror(error);
        };
        jacslog(`[${this.proxyId}] CONSTRUCTOR: Transport proxy initialized.`);
        if ('send' in this.transport && typeof this.transport.send === 'function') {
            const originalSend = this.transport.send.bind(this.transport);
            this.transport.send = async (data) => {
                if (typeof data === 'string') {
                    // Check if this is a server-side SSE transport
                    const sseTransport = this.transport;
                    if (sseTransport._sseResponse) {
                        // Server-side: write directly to SSE stream
                        sseTransport._sseResponse.write(`event: message\ndata: ${data}\n\n`);
                        return;
                    }
                    else if (sseTransport._endpoint) {
                        // Client-side: use fetch (existing code)
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
                return originalSend(data);
            };
        }
        // Replace the client monkey patch section in the constructor with this:
        if (role === "client") {
            jacslog(`[${this.proxyId}] Setting up EventSource interception for client...`);
            // Wait for the transport to be initialized, then intercept its EventSource
            setTimeout(() => {
                const sseTransport = this.transport;
                if (sseTransport._eventSource) {
                    jacslog(`[${this.proxyId}] Found EventSource, intercepting onmessage...`);
                    const originalOnMessage = sseTransport._eventSource.onmessage;
                    sseTransport._eventSource.onmessage = async (event) => {
                        jacslog(`[${this.proxyId}] EventSource received message:`, event.data?.substring(0, 100));
                        try {
                            // Try JACS verification first
                            if (this.jacsOperational) {
                                const verificationResult = await index_js_1.default.verifyResponse(event.data);
                                let decryptedMessage;
                                if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
                                    decryptedMessage = verificationResult.payload;
                                }
                                else {
                                    decryptedMessage = verificationResult;
                                }
                                // Clean up JACS-added null values before passing to MCP SDK
                                const cleanedMessage = this.removeNullValues(decryptedMessage);
                                jacslog(`[${this.proxyId}] JACS verification successful, passing decrypted message to MCP SDK`);
                                const newEvent = new MessageEvent('message', {
                                    data: JSON.stringify(cleanedMessage)
                                });
                                originalOnMessage.call(sseTransport._eventSource, newEvent);
                                return;
                            }
                        }
                        catch (jacsError) {
                            jacslog(`[${this.proxyId}] Not a JACS artifact, passing original message to MCP SDK`);
                        }
                        // Not JACS or JACS failed, use original handler
                        originalOnMessage.call(sseTransport._eventSource, event);
                    };
                }
                else {
                    jacslog(`[${this.proxyId}] EventSource not found, will retry...`);
                    // Retry after transport is fully initialized
                    setTimeout(() => {
                        if (this.transport._eventSource) {
                            jacslog(`[${this.proxyId}] Found EventSource on retry, intercepting...`);
                            // Same logic as above
                        }
                    }, 100);
                }
            }, 50);
        }
    }
    async start() {
        jacslog(`[${this.proxyId}] Starting underlying transport...`);
        return this.transport.start();
    }
    async close() {
        jacslog(`[${this.proxyId}] Closing underlying transport...`);
        return this.transport.close();
    }
    // Intercept outgoing messages to the transport
    async send(message) {
        const logPrefix = `[${this.proxyId}] OUTGOING`;
        try {
            if (enableDiagnosticLogging)
                jacslog(`${logPrefix}: MCP SDK sending message: ${JSON.stringify(message).substring(0, 100)}...`);
            if (this.jacsOperational) {
                // Skip JACS for error responses
                if ('error' in message) {
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: Error response, skipping JACS encryption.`);
                    await this.transport.send(message);
                }
                else {
                    try {
                        if (enableDiagnosticLogging)
                            jacslog(`${logPrefix}: Applying JACS encryption to message...`);
                        // Clean up the message before JACS signing - remove null params
                        const cleanMessage = { ...message };
                        if ('params' in cleanMessage && cleanMessage.params === null) {
                            delete cleanMessage.params;
                        }
                        const jacsArtifact = await index_js_1.default.signRequest(cleanMessage);
                        await this.transport.send(jacsArtifact);
                    }
                    catch (jacsError) {
                        console.error(`${logPrefix}: JACS encryption failed, sending plain message. Error:`, jacsError);
                        await this.transport.send(message);
                    }
                }
            }
            else {
                if (enableDiagnosticLogging)
                    jacslog(`${logPrefix}: JACS not operational, sending plain message.`);
                await this.transport.send(message);
            }
            if (enableDiagnosticLogging)
                jacslog(`${logPrefix}: Successfully sent to transport.`);
        }
        catch (error) {
            console.error(`${logPrefix}: Error sending message:`, error);
            throw error;
        }
    }
    // Forward transport properties
    get sessionId() {
        return this.transport.sessionId;
    }
    // Handle HTTP POST for SSE transports (if applicable)
    /**
     * REQUIRED for SSE (Server-Sent Events) transport pattern in MCP.
     *
     * WHY THIS EXISTS:
     * SSE is inherently unidirectional (server→client), but MCP requires bidirectional communication.
     * The MCP SSE implementation solves this with a hybrid approach:
     * - Server→Client: Uses SSE stream for real-time messages
     * - Client→Server: Uses HTTP POST to a specific endpoint
     *
     * This function intercepts those client POST requests, decrypts JACS payloads,
     * and forwards the decrypted messages to the underlying SSE transport handler.
     *
     * Without this, JACS-encrypted client messages would never reach the MCP server.
     */
    async handlePostMessage(req, res, rawBodyString) {
        const logPrefix = `[${this.proxyId}] HTTP_POST`;
        // Verify the underlying transport actually supports POST handling
        // (not all MCP transports do - only SSE transports need this)
        if (!('handlePostMessage' in this.transport) || typeof this.transport.handlePostMessage !== 'function') {
            console.error(`${logPrefix}: Underlying transport does not support handlePostMessage`);
            if (!res.writableEnded)
                res.writeHead(500).end("Transport does not support POST handling");
            return;
        }
        // Extract the request body (which contains the JACS-encrypted payload)
        let bodyToProcess;
        if (rawBodyString !== undefined) {
            // Body already provided (likely from Express middleware)
            bodyToProcess = rawBodyString;
        }
        else {
            // Manually read the request body from the HTTP stream
            const bodyBuffer = [];
            for await (const chunk of req) {
                bodyBuffer.push(chunk);
            }
            bodyToProcess = Buffer.concat(bodyBuffer).toString();
            if (!bodyToProcess) {
                if (!res.writableEnded)
                    res.writeHead(400).end("Empty body");
                return;
            }
        }
        if (enableDiagnosticLogging)
            jacslog(`${logPrefix}: Raw body (len ${bodyToProcess.length}): ${bodyToProcess.substring(0, 100)}...`);
        // Add this debug line before calling jacs.verifyResponse:
        jacslog(`${logPrefix}: JACS Debug - Body type: ${typeof bodyToProcess}`);
        jacslog(`${logPrefix}: JACS Debug - First 200 chars:`, JSON.stringify(bodyToProcess.substring(0, 200)));
        jacslog(`${logPrefix}: JACS Debug - Is valid JSON?`, (() => {
            try {
                JSON.parse(bodyToProcess);
                return true;
            }
            catch {
                return false;
            }
        })());
        try {
            let processedBody = bodyToProcess;
            if (this.jacsOperational) {
                // Try normalizing the JSON string before JACS verification:
                try {
                    // First, try to parse and re-stringify to normalize
                    const parsedJson = JSON.parse(bodyToProcess);
                    const normalizedJsonString = JSON.stringify(parsedJson);
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: Attempting JACS verification with normalized JSON...`);
                    const verificationResult = await index_js_1.default.verifyResponse(normalizedJsonString);
                    let decryptedMessage;
                    if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
                        decryptedMessage = verificationResult.payload;
                    }
                    else {
                        decryptedMessage = verificationResult;
                    }
                    // Clean up JACS-added null params before passing to MCP SDK
                    if ('params' in decryptedMessage && decryptedMessage.params === null) {
                        const cleanMessage = { ...decryptedMessage };
                        delete cleanMessage.params;
                        processedBody = JSON.stringify(cleanMessage);
                    }
                    else {
                        processedBody = JSON.stringify(decryptedMessage);
                    }
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: JACS verification successful. Decrypted to: ${processedBody.substring(0, 100)}...`);
                }
                catch (parseError) {
                    // If it's not valid JSON, try with original string
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: JSON normalization failed, trying original string...`);
                    const verificationResult = await index_js_1.default.verifyResponse(bodyToProcess);
                    let decryptedMessage;
                    if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
                        decryptedMessage = verificationResult.payload;
                    }
                    else {
                        decryptedMessage = verificationResult;
                    }
                    // Clean up JACS-added null params before passing to MCP SDK
                    if ('params' in decryptedMessage && decryptedMessage.params === null) {
                        const cleanMessage = { ...decryptedMessage };
                        delete cleanMessage.params;
                        processedBody = JSON.stringify(cleanMessage);
                    }
                    else {
                        processedBody = JSON.stringify(decryptedMessage);
                    }
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: JACS verification successful. Decrypted to: ${processedBody.substring(0, 100)}...`);
                }
            }
            // Forward to underlying transport's POST handler
            await this.transport.handlePostMessage(req, res, processedBody);
        }
        catch (error) {
            console.error(`${logPrefix}: Error processing POST:`, error);
            if (!res.writableEnded) {
                const errorMessage = error instanceof Error ? error.message : "Unknown error";
                res.writeHead(500).end(`Error: ${errorMessage}`);
            }
        }
    }
    async handleIncomingMessage(incomingData) {
        const logPrefix = `[${this.proxyId}] INCOMING`;
        try {
            let messageForSDK;
            if (typeof incomingData === 'string') {
                if (enableDiagnosticLogging)
                    jacslog(`${logPrefix}: Received string from transport (len ${incomingData.length}): ${incomingData.substring(0, 100)}...`);
                if (this.jacsOperational) {
                    try {
                        if (enableDiagnosticLogging)
                            jacslog(`${logPrefix}: Attempting JACS verification of string...`);
                        const verificationResult = await index_js_1.default.verifyResponse(incomingData);
                        let decryptedMessage;
                        if (verificationResult && typeof verificationResult === 'object' && 'payload' in verificationResult) {
                            decryptedMessage = verificationResult.payload;
                        }
                        else {
                            decryptedMessage = verificationResult;
                        }
                        if (enableDiagnosticLogging)
                            jacslog(`${logPrefix}: JACS verification successful. Decrypted message: ${JSON.stringify(decryptedMessage).substring(0, 100)}...`);
                        messageForSDK = decryptedMessage;
                    }
                    catch (jacsError) {
                        const errorMessage = jacsError instanceof Error ? jacsError.message : "Unknown JACS error";
                        if (enableDiagnosticLogging)
                            jacslog(`${logPrefix}: Not a JACS artifact, parsing as plain JSON. JACS error was: ${errorMessage}`);
                        messageForSDK = JSON.parse(incomingData);
                    }
                }
                else {
                    if (enableDiagnosticLogging)
                        jacslog(`${logPrefix}: JACS not operational, parsing as plain JSON.`);
                    messageForSDK = JSON.parse(incomingData);
                }
            }
            else if (typeof incomingData === 'object' && incomingData !== null && 'jsonrpc' in incomingData) {
                if (enableDiagnosticLogging)
                    jacslog(`${logPrefix}: Received object from transport, using as-is.`);
                messageForSDK = incomingData;
            }
            else {
                console.error(`${logPrefix}: Unexpected data type from transport:`, typeof incomingData);
                throw new Error("Invalid data type from transport");
            }
            if (enableDiagnosticLogging)
                jacslog(`${logPrefix}: Passing to MCP SDK: ${JSON.stringify(messageForSDK).substring(0, 100)}...`);
            if (this.onmessage) {
                this.onmessage(messageForSDK);
            }
        }
        catch (error) {
            console.error(`${logPrefix}: Error processing incoming message:`, error);
            if (this.onerror)
                this.onerror(error);
        }
    }
    /**
     * Removes null and undefined values from JSON objects to prevent MCP schema validation failures.
     *
     * WORKAROUND for MCP JSON Schema validation issues:
     * - Addresses strict validators (like Anthropic's API) that reject schemas with null values
     * - Handles edge cases where tools have null inputSchema causing client validation errors
     * - Prevents "invalid_type: expected object, received undefined" errors in TypeScript SDK v1.9.0
     * - Cleans up malformed schemas before transmission to avoid -32602 JSON-RPC errors
     *
     * Related issues:
     * - https://github.com/modelcontextprotocol/typescript-sdk/issues/400 (null schema tools)
     * - https://github.com/anthropics/claude-code/issues/586 (Anthropic strict Draft 2020-12)
     * - https://github.com/agno-agi/agno/issues/2791 (missing type field)
     *
     * @param obj - The object to clean (typically MCP tool/resource schemas)
     * @returns A new object with all null/undefined values recursively removed
     */
    removeNullValues(obj) {
        if (obj === null || obj === undefined)
            return undefined;
        if (typeof obj !== 'object')
            return obj;
        if (Array.isArray(obj))
            return obj.map(item => this.removeNullValues(item));
        const cleaned = {};
        for (const [key, value] of Object.entries(obj)) {
            const cleanedValue = this.removeNullValues(value);
            if (cleanedValue !== null && cleanedValue !== undefined) {
                cleaned[key] = cleanedValue;
            }
        }
        return cleaned;
    }
}
exports.JACSTransportProxy = JACSTransportProxy;
// Factory functions
function createJACSTransportProxy(transport, configPath, role) {
    jacslog(`Creating JACS Transport Proxy for role: ${role}`);
    return new JACSTransportProxy(transport, role, configPath);
}
exports.createJACSTransportProxy = createJACSTransportProxy;
async function createJACSTransportProxyAsync(transport, configPath, role) {
    jacslog(`Creating JACS Transport Proxy (async) for role: ${role}`);
    await ensureJacsLoaded(configPath);
    return new JACSTransportProxy(transport, role, configPath);
}
exports.createJACSTransportProxyAsync = createJACSTransportProxyAsync;
//# sourceMappingURL=mcp.js.map