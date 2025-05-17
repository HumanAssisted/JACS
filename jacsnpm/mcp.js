import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Server as CoreMcpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import jacsNapiInstance from './index.js'; // Import the NAPI instance at the module level


/**
 * Creates a transport wrapper for JACS request/response handling
 * @param {Object} transport - The original MCP transport
 * @param {Object} options
 * @param {string} [options.configPath] - Path to JACS config file
 */
export function createJacsTransport(transport, options = {}) {
    const originalSend = transport.send.bind(transport);
    
    transport.send = async (msg) => { // msg is the original JSON-RPC object
        const jacs = await import('./index.js');
        
        if (options.configPath) { 
            try {
                console.log(`JACS Client: Loading JACS config from ${options.configPath}`);
                await jacs.load(options.configPath); 
                console.log("JACS Client: JACS config loaded successfully");
            } catch (e) {
                console.error(`JACS Client: FATAL - Failed to load JACS config ${options.configPath}`, e);
                throw e; 
            }
        }

        let jacsDocumentStringForRequest;
        try {
            // Client signs the JSON-RPC message object
            jacsDocumentStringForRequest = await jacs.signRequest(msg);
            console.log("JACS Client: JACS Document String prepared for sending (first 100 chars):", jacsDocumentStringForRequest.substring(0,100) + "...");
        } catch (signingError) {
            console.error("JACS Client: ERROR signing entire request object:", signingError);
             return {
                jsonrpc: "2.0",
                id: msg.id || null,
                error: {
                    code: -32010, 
                    message: `JACS Client: Failed to sign request object: ${signingError.message}`,
                    data: signingError.toString() 
                }
            };
        }
        
        console.log("JACS Client: Sending JACS Document String to server (via originalSend) (first 100 chars):", jacsDocumentStringForRequest.substring(0,100) + "...");
        const rawServerResponse = await originalSend(jacsDocumentStringForRequest); 
        
        if (typeof rawServerResponse === 'undefined') {
            console.warn(`JACS Client: WARNING - originalSend for request (id=${msg.id}, method=${msg.method}) returned undefined.`);
            if (msg.hasOwnProperty('id')) { 
                return { 
                    jsonrpc: "2.0", 
                    id: msg.id, 
                    error: { 
                        code: -32005, 
                        message: "Client Error: No JACS response or undefined response received from server's transport layer." 
                    } 
                };
            }
            return undefined; 
        } else if (rawServerResponse && rawServerResponse.jsonrpc && rawServerResponse.error && typeof rawServerResponse.error.code === 'number') {
            console.warn(`JACS Client: originalSend returned a JSON-RPC error object directly:`, JSON.stringify(rawServerResponse, null, 2));
            return rawServerResponse;
        } else if (typeof rawServerResponse !== 'string') {
            console.error("JACS Client: ERROR - Expected JACS Document String from server, but received non-string:", typeof rawServerResponse, rawServerResponse);
            return { 
                jsonrpc: "2.0", 
                id: msg.id || null, 
                error: { 
                    code: -32009, 
                    message: "Client Error: Did not receive a JACS Document String from server. Received type: " + typeof rawServerResponse,
                    data: String(rawServerResponse).substring(0, 200)
                } 
            };
        } else {
            console.log("JACS Client: Received raw JACS Document String from server (first 100 chars):", rawServerResponse.substring(0,100) + "...");
        }

        let finalRpcResponseObject;
        try {
            // Client verifies the JACS Document String from the server
            let verified_response = await jacs.verifyResponse(rawServerResponse); 
            finalRpcResponseObject = verified_response.payload;

            if (!finalRpcResponseObject || typeof finalRpcResponseObject !== 'object' || !finalRpcResponseObject.jsonrpc) {
                console.error("JACS Client: ERROR - Verified response is not a valid JSON-RPC object:", finalRpcResponseObject);
                finalRpcResponseObject = {
                    jsonrpc: "2.0",
                    id: msg.id || null,
                    error: {
                        code: -32011, 
                        message: "Client Error: JACS verification of server response did not yield a valid JSON-RPC object.",
                        data: JSON.stringify(finalRpcResponseObject)
                    }
                };
            }
        } catch (verificationError) {
            console.error("JACS Client: Error verifying server's JACS Document String:", verificationError);
            finalRpcResponseObject = { 
                jsonrpc: "2.0", 
                id: msg.id || null, 
                error: { 
                    code: -32006, 
                    message: "Client Error: Failed to verify JACS signature on server response.", 
                    data: verificationError.message 
                } 
            };
        }
        
        return finalRpcResponseObject;
    };
    return transport;
}

/**
 * Extended MCP Server with built-in JACS support
 */
export class JacsMcpServer extends McpServer {
    /**
     * @param {Object} options
     * @param {string} options.name - Server name
     * @param {string} options.version - Server version
     * @param {string} [options.configPath] - Path to JACS config
     * @param {Object} [options.transport] - Custom transport
     */
    constructor(options) {
        super(
            { name: options.name, version: options.version },
            options.serverOptions
        );

        this.configPath = options.configPath;
        this.jacsAgent = null;
        console.log(`JacsMcpServer Constructor: Initialized. Config path: '${this.configPath}'`);

        // Store the transport from constructor options
        if (!options.transport) {
            // If no transport is provided in options, you might default or error.
            // Your example mcp.server.js *does* provide options.transport.
            console.warn("JacsMcpServer constructor: options.transport is undefined. Using default StdioServerTransport.");
            this.storedTransport = new StdioServerTransport(); 
        } else {
            this.storedTransport = options.transport;
        }
    }

    /**
     * Load the JACS agent
     */
    async loadJacsAgent() {
        if (!this.configPath) {
            console.error("JacsMcpServer.loadJacsAgent: configPath not provided.");
            return false;
        }
        if (this.jacsAgent) {
            console.log("JacsMcpServer.loadJacsAgent: JACS agent already loaded.");
            return true;
        }
        console.log(`JacsMcpServer.loadJacsAgent: Attempting to load JACS NAPI and config from '${this.configPath}'`);
        try {
            // Use the module-level jacsNapiInstance.
            // The load call configures this shared instance.
            console.log(`JacsMcpServer.loadJacsAgent: Loading JACS NAPI instance with config: ${this.configPath}`);
            await jacsNapiInstance.load(this.configPath);
            this.jacsAgent = jacsNapiInstance; // Assign the configured NAPI instance
            console.log("JacsMcpServer.loadJacsAgent: JACS NAPI instance configured and assigned to this.jacsAgent.");
            return true;
        } catch (error) {
            console.error(`JacsMcpServer.loadJacsAgent: CRITICAL - Failed to load JACS agent from ${this.configPath}.`, error);
            this.jacsAgent = null;
            return false;
        }
    }

    /**
     * Connect the server to its transport
     */
    async connect() {
        console.log("JacsMcpServer.connect: Attempting to load JACS agent...");
        const agentLoaded = await this.loadJacsAgent();
        if (!agentLoaded || !this.jacsAgent) {
            console.error("JacsMcpServer.connect: Critical JACS agent failed to load. Server cannot start securely.");
            throw new Error("JacsMcpServer.connect: Critical JACS agent failed to load.");
        }

        if (!this.storedTransport) {
            // This should ideally be caught in the constructor if options.transport was mandatory
            throw new Error("JacsMcpServer.connect: Stored transport is undefined. It should have been set in the constructor from options.transport.");
        }

        // McpServer.connect(transport) internally calls this.server.connect(transport).
        // We call super.connect() and pass it the transport we stored from the constructor.
        console.log("JacsMcpServer.connect: Calling super.connect with stored transport.");
        await super.connect(this.storedTransport); 
        
        console.log("JacsMcpServer.connect: Server connection to transport successful.");
    }

    /**
     * Handle a request
     * @param {string|Object} request - Raw request (JACS document string or parsed JSON)
     */
    async handle(requestString) {
        let requestId = null;
        try {
            const preParse = JSON.parse(requestString);
            if (preParse && typeof preParse === 'object' && preParse.jacs_payload && typeof preParse.jacs_payload === 'object' && preParse.jacs_payload.hasOwnProperty('id')) {
                requestId = preParse.jacs_payload.id;
            }
        } catch (e) { /* Potentially not a JACS string or not plain JSON, ID might be found later */ }

        if (!this.jacsAgent) {
            console.error("JacsMcpServer.handle: CRITICAL - this.jacsAgent is null. Ensure loadJacsAgent was successful during connect.");
            const err = { jsonrpc: "2.0", id: requestId, error: { code: -32002, message: "JACS agent not available" }};
            return JSON.stringify(err);
        }

        let jsonRpcPayload;
        try {
            if (typeof requestString !== 'string') {
                console.error(`JacsMcpServer.handle: Input 'requestString' is not a string (type: ${typeof requestString}). This is unexpected.`);
                throw new Error("Invalid input: requestString must be a string for JACS verification.");
            }
            console.log(`JacsMcpServer.handle: Attempting JACS verification. Input string length: ${requestString.length}.`);
            // --- THE CRITICAL CALL ---
            const verificationResult = await this.jacsAgent.verifyResponse(requestString);
            // --- END CRITICAL CALL ---
            console.log("JacsMcpServer.handle: jacsAgent.verifyResponse returned:", JSON.stringify(verificationResult));

            if (!verificationResult || typeof verificationResult !== 'object' || !verificationResult.hasOwnProperty('payload')) {
                console.error("JacsMcpServer.handle: Invalid result from jacsAgent.verifyResponse. Expected object with 'payload', got:", verificationResult);
                throw new Error("JACS verification failed: result structure incorrect (missing payload).");
            }
            jsonRpcPayload = verificationResult.payload;
            if (typeof jsonRpcPayload !== 'object' || jsonRpcPayload === null) {
                console.error("JacsMcpServer.handle: 'payload' from JACS verification is not an object. Payload:", jsonRpcPayload);
                throw new Error("JACS verification failed: payload is not an object.");
            }
            if (jsonRpcPayload.hasOwnProperty('id')) requestId = jsonRpcPayload.id; // Update ID from verified payload
            console.log("JacsMcpServer.handle: JACS document verified successfully. Payload extracted.");

        } catch (jacsError) {
            console.error(`JacsMcpServer.handle: Error during jacsAgent.verifyResponse stage. Message: ${jacsError.message}`, jacsError.stack);
            const err = { jsonrpc: "2.0", id: requestId, error: { code: -32700, message: `JACS verification error: ${jacsError.message}` }};
            try { return await this.jacsAgent.signRequest(err); }
            catch (signErr) { console.error("JacsMcpServer.handle: Failed to sign verification error:", signErr); return JSON.stringify(err); }
        }

        if (!jsonRpcPayload || typeof jsonRpcPayload.method !== 'string') {
            console.error("JacsMcpServer.handle: Invalid JSON-RPC payload after verification (e.g., missing 'method'). Payload:", jsonRpcPayload);
            const err = { jsonrpc: "2.0", id: requestId, error: { code: -32600, message: "Invalid JSON-RPC structure in JACS payload." }};
            try { return await this.jacsAgent.signRequest(err); }
            catch (signErr) { return JSON.stringify(err); }
        }

        let mcpResponseObject;
        if (this.server && typeof this.server['receiveRequest'] === 'function') {
            try {
                if ('method' in jsonRpcPayload && 'id' in jsonRpcPayload) {
                    mcpResponseObject = await this.server['receiveRequest'](jsonRpcPayload);
                } else if ('method' in jsonRpcPayload) {
                    await this.server['receiveNotification'](jsonRpcPayload);
                    mcpResponseObject = undefined;
                } else {
                    throw new Error("Invalid JSON-RPC message structure");
                }
            } catch (processingError) {
                console.error("JacsMcpServer.handle: Error processing request via this.server.receiveRequest/Notification:", processingError);
                mcpResponseObject = {
                    jsonrpc: "2.0",
                    id: requestId,
                    error: { code: -32603, message: `Internal error processing request: ${processingError.message}` }
                };
            }
        } else {
            console.error("JacsMcpServer.handle: CRITICAL - this.server (CoreMcpServer) does not have a 'receiveRequest' or 'receiveNotification' method or is undefined.");
            mcpResponseObject = {
                jsonrpc: "2.0",
                id: requestId,
                error: { code: -32000, message: "Server misconfiguration: Cannot process request." }
            };
        }

        if (mcpResponseObject === undefined) {
            return undefined;
        }

        try {
            console.log("JacsMcpServer.handle: Signing JACS response");
            return await this.jacsAgent.signRequest(mcpResponseObject);
        } catch (signingError) {
            console.error("JacsMcpServer.handle: Error JACS-signing response:", signingError);
            const err = { jsonrpc: "2.0", id: requestId, error: { code: -32003, message: `Failed to sign JACS response: ${signingError.message}` }};
            return JSON.stringify(err); 
        }
    }
}

/**
 * Extended MCP Client with built-in JACS support
 */
export class JacsMcpClient extends Client {
    /**
     * @param {Object} options
     * @param {string} options.name - Client name
     * @param {string} options.version - Client version
     * @param {string} [options.url] - Server URL (for HTTP transport)
     * @param {string} [options.command] - Command to run for Stdio transport (e.g., "node")
     * @param {string[]} [options.args] - Arguments for the command for Stdio transport (e.g., ["server.js"])
     * @param {string} [options.configPath] - Path to JACS config
     * @param {Record<string, string>} [options.stdioEnv] - Environment variables for Stdio transport's child process
     */
    constructor(options) {
        super({
            name: options.name,
            version: options.version
        });

        this.serverUrl = options.url;
        this.configPath = options.configPath;
        this.command = options.command;
        this.args = options.args;
        this.stdioEnv = options.stdioEnv;
        console.log(`JacsMcpClient Constructor: Initialized. URL='${this.serverUrl}'. Command='${this.command}'. Config path: \'${this.configPath}\'. StdioEnv provided: ${!!this.stdioEnv}`);
    }

    /**
     * Connects the client to the server
     */
    async connect() {
        let baseTransport;
        if (this.serverUrl) {
            // HTTP Transport
            if (this.command || this.args) {
                console.warn("JacsMcpClient.connect: 'url' is provided, 'command' and 'args' will be ignored for HTTP transport.");
            }
            let serverUrlObject;
            try {
                serverUrlObject = new URL(this.serverUrl);
            } catch (e) {
                throw new Error(`JacsMcpClient.connect: Invalid server URL \'${this.serverUrl}\': ${e.message}`);
            }
            console.log(`JacsMcpClient.connect: Creating StreamableHTTPClientTransport for URL: ${serverUrlObject.href}`);
            baseTransport = new StreamableHTTPClientTransport(serverUrlObject);
        } else if (this.command && this.args) {
            // Stdio Transport
            console.log(`JacsMcpClient.connect: Creating StdioClientTransport with command: '${this.command}', args: [${this.args.join(', ')}]`);
            baseTransport = new StdioClientTransport({
                command: this.command,
                args: this.args,
                env: this.stdioEnv 
            });
        } else {
            throw new Error("JacsMcpClient.connect: Insufficient options. Provide 'url' for HTTP transport, or 'command' and 'args' for Stdio transport.");
        }
        
        console.log(`JacsMcpClient.connect: Wrapping base transport with JACS. Config path for JACS: \'${this.configPath}\'`);
        const jacsWrappedTransport = createJacsTransport(baseTransport, {
            configPath: this.configPath 
        });
        
        console.log("JacsMcpClient.connect: Attempting super.connect with JACS-wrapped transport...");
        await super.connect(jacsWrappedTransport);
        console.log("JacsMcpClient.connect: Successfully connected to server.");
    }

    /**
     * Checks if the client is currently connected to a transport.
     * @returns {boolean} True if connected, false otherwise.
     */
    isConnected() {
        return this.transport !== undefined;
    }

    /**
     * Closes the connection to the server.
     * For StdioClientTransport, this will also terminate the child process.
     */
    async close() {
        if (this.transport) {
            await this.transport.close(); // The base Client's connect method should set this.transport
            // The base Client's _onclose handler will set this.transport to undefined.
            // If direct manipulation is needed and not handled by SDK's close:
            // this.transport = undefined; 
        }
    }
}