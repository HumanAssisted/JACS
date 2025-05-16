// File: JACS/jacsnpm/mcp.js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

/**
 * Creates middleware for JACS request/response signing and verification
 * @param {Object} options
 * @param {string} [options.configPath] - Path to JACS config file
 */
export function createJacsMiddleware(options = {}) {
    return async (ctx, next) => {
        const jacs = await import('./index.js');
        if (options.configPath) { await jacs.load(options.configPath); }
        if (ctx.request) {
            try { ctx.request = jacs.verifyResponse(ctx.request); }
            catch (error) { throw new Error(`Invalid JACS request: ${error.message}`); }
        }
        await next();
        if (ctx.response) {
            try { ctx.response = jacs.signRequest(ctx.response); }
            catch (error) { throw new Error(`Failed to sign response: ${error.message}`); }
        }
    };
}

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
                console.log("JACS Client: JACS config loaded successfully.");
            } catch (e) {
                console.error(`JACS Client: FATAL - Failed to load JACS config ${options.configPath}`, e);
                throw e; 
            }
        }

        console.log("JACS Client: Original MCP JSON-RPC message to sign & send:", JSON.stringify(msg, null, 2));
        
        let jacsDocumentStringForRequest;
        try {
            // Sign the entire original JSON-RPC message object
            // Assuming jacs.signRequest takes the object and returns the JACS Document String
            jacsDocumentStringForRequest = await jacs.signRequest(msg);
            console.log("JACS Client: JACS Document String prepared for sending (first 100 chars):", jacsDocumentStringForRequest.substring(0,100) + "...");
        } catch (signingError) {
            console.error("JACS Client: ERROR signing entire request object:", signingError);
            // If signing fails, we can't proceed with this request securely.
            // Propagate a meaningful error.
            // Make sure to return a JSON-RPC compliant error if possible, or rethrow.
             return {
                jsonrpc: "2.0",
                id: msg.id || null, // Use original request ID if available
                error: {
                    code: -32010, // Custom client-side error for JACS signing failure
                    message: `JACS Client: Failed to sign request object: ${signingError.message}`,
                    data: signingError.toString() 
                }
            };
        }
        
        // Send the JACS Document String as the raw request body.
        console.log("JACS Client: Sending JACS Document String to server (via originalSend) (first 100 chars):", jacsDocumentStringForRequest.substring(0,100) + "...");
        const rawServerResponse = await originalSend(jacsDocumentStringForRequest); 
        // ^^^ We now expect rawServerResponse to be the JACS Document String from the server OR undefined on error/no response
        
        if (typeof rawServerResponse === 'undefined') {
            console.warn(`JACS Client: WARNING - originalSend for request (id=${msg.id}, method=${msg.method}) returned undefined. Expected JACS Document String or specific error object from transport.`);
            if (msg.hasOwnProperty('id')) { 
                console.error(`JACS Client: ERROR - originalSend returned undefined for a request that expected a JACS response.`);
                // This is the case where the transport itself gives up or returns nothing.
                return { 
                    jsonrpc: "2.0", 
                    id: msg.id, 
                    error: { 
                        code: -32005, 
                        message: "Client Error: No JACS response or undefined response received from server's transport layer." 
                    } 
                };
            } else { 
                console.log(`JACS Client: Notification ${msg.method} sent. No JACS response expected, and originalSend returned undefined.`);
                return undefined; 
            }
        } else if (rawServerResponse && rawServerResponse.jsonrpc && rawServerResponse.error && typeof rawServerResponse.error.code === 'number') {
            // This checks if originalSend itself returned a JSON-RPC error object (e.g. from StreamableHTTPClientTransport due to HTTP error)
            console.warn(`JACS Client: originalSend returned a JSON-RPC error object directly:`, JSON.stringify(rawServerResponse, null, 2));
            return rawServerResponse; // Pass this error through
        } else if (typeof rawServerResponse !== 'string') {
             // This is an unexpected response type from originalSend if it's not undefined and not a JACS string
            console.error("JACS Client: ERROR - Expected JACS Document String from server, but received non-string:", typeof rawServerResponse, rawServerResponse);
            return { 
                jsonrpc: "2.0", 
                id: msg.id || null, 
                error: { 
                    code: -32009, 
                    message: "Client Error: Did not receive a JACS Document String from server as expected. Received type: " + typeof rawServerResponse,
                    data: String(rawServerResponse).substring(0, 200) // Include snippet of what was received
                } 
            };
        } else {
            console.log("JACS Client: Received raw JACS Document String from server (first 100 chars):", rawServerResponse.substring(0,100) + "...");
        }

        // Now, rawServerResponse should be the JACS Document String from the server.
        let finalRpcResponseObject;
        // No need to check typeof rawServerResponse === 'string' again due to previous conditional block
        console.log("JACS Client: Response is a string. Assuming JACS Document. Verifying with jacs.verifyResponse.");
        try {
            finalRpcResponseObject = await jacs.verifyResponse(rawServerResponse); // rawServerResponse IS a string here
            console.log("JACS Client: Verified JSON-RPC response object from server:", JSON.stringify(finalRpcResponseObject, null, 2));
            
            if (!finalRpcResponseObject || typeof finalRpcResponseObject !== 'object' || !finalRpcResponseObject.jsonrpc) {
                console.error("JACS Client: ERROR - Verified response is not a valid JSON-RPC object:", finalRpcResponseObject);
                // Construct a JSON-RPC error to return to the application
                finalRpcResponseObject = {
                    jsonrpc: "2.0",
                    id: msg.id || null, // Try to preserve ID
                    error: {
                        code: -32011, // Custom error: verification yielded invalid RPC
                        message: "Client Error: JACS verification of server response did not yield a valid JSON-RPC object.",
                        data: JSON.stringify(finalRpcResponseObject) // show what was actually parsed
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
        
        console.log("JACS Client: Final processed JSON-RPC response to return to application:", JSON.stringify(finalRpcResponseObject, null, 2));
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
     * @param {Object} [options.transport] - Custom transport (defaults to StdioServerTransport)
     */
    constructor(options) {
        const transportInstance = options.transport || new StdioServerTransport();
        
        super({
            name: options.name,
            version: options.version
        });

        this.configPath = options.configPath;
        this.explicitTransport = transportInstance;
        this.jacsAgent = null;
        console.log(`JacsMcpServer Constructor: Initialized name='${options.name}', version='${options.version}'. Explicit transport set. Config path: '${this.configPath}'`);
    }

    async loadJacsAgent() {
        if (!this.configPath) {
            console.error("JacsMcpServer.loadJacsAgent: configPath not provided. JACS agent cannot be loaded.");
            return false; 
        }
        if (this.jacsAgent) {
            console.log("JacsMcpServer.loadJacsAgent: JACS agent already loaded.");
            return true;
        }
        console.log(`JacsMcpServer.loadJacsAgent: Attempting to load JACS NAPI and config from '${this.configPath}'`);
        try {
            const jacs = await import('./index.js'); 
            await jacs.load(this.configPath);
            this.jacsAgent = jacs; 
            console.log("JacsMcpServer.loadJacsAgent: JACS agent loaded successfully from:", this.configPath);
            return true;
        } catch (error) {
            console.error(`JacsMcpServer.loadJacsAgent: CRITICAL - Failed to load JACS agent from ${this.configPath}.`, error);
            this.jacsAgent = null;
            return false;
        }
    }

    /**
     * Connects the server using the configured transport.
     */
    async connect() {
        console.log("JacsMcpServer.connect: Process started. Attempting to load JACS agent...");
        const agentLoaded = await this.loadJacsAgent();
        if (!agentLoaded || !this.jacsAgent) {
            console.error("JacsMcpServer.connect: Critical JACS agent failed to load. Server cannot start securely.");
            throw new Error("JacsMcpServer.connect: Critical JACS agent failed to load. Server cannot start securely.");
        }

        if (!this.explicitTransport) {
            console.error("JacsMcpServer.connect: explicitTransport is not set. This is required.");
            throw new Error("JacsMcpServer.connect: Transport not initialized or configured.");
        }
        
        console.log("JacsMcpServer.connect: JACS Agent loaded. Connecting server to its explicit transport...");
        await super.connect(this.explicitTransport); 
        console.log("JacsMcpServer.connect: Server connection to transport successful.");
    }

    async handle(request) { 
        if (!this.jacsAgent) {
            console.error("JacsMcpServer.handle: CRITICAL - JACS agent not available!");
            // Return a JACS-signed error if possible, otherwise a raw error string might be the only option
            // For now, this is a plain object. The transport layer (StreamableHTTPServerTransport)
            // will JSON.stringify this. If we want this error itself JACS signed, it's more complex here.
            // However, the client might not be able to JACS-verify it if the agent itself is the problem.
             return { 
                jsonrpc: "2.0", 
                id: request.id || null, 
                error: { code: -32002, message: "Internal server error: JACS agent unavailable for response signing." } 
            };
        }
        
        // 'request' is the actual JSON-RPC object, already verified and unwrapped by the HTTP layer in mcp.server.js
        console.log("JacsMcpServer.handle: Received verified JSON-RPC request:", JSON.stringify(request, null, 2));
        
        // Get the standard JSON-RPC response object from the core MCP server logic
        const mcpResponseObject = await super.handle(request); 
        console.log("JacsMcpServer.handle: JSON-RPC response from super.handle (to be JACS-signed):", JSON.stringify(mcpResponseObject, null, 2));

        try {
            // Sign the entire JSON-RPC response object
            // Assuming this.jacsAgent.signResponse takes an object and returns a JACS Document String
            const jacsDocumentStringResponse = await this.jacsAgent.signResponse(mcpResponseObject);
            console.log("JacsMcpServer.handle: Returning JACS Document String to transport layer (first 100 chars):", jacsDocumentStringResponse.substring(0,100) + "...");
            
            // This JACS Document String will be sent as the raw HTTP response body by StreamableHTTPServerTransport
            return jacsDocumentStringResponse; 

        } catch (signingError) {
            console.error("JacsMcpServer.handle: CRITICAL - Error JACS-signing the mcpResponseObject:", signingError);
            // If signing the actual response fails, we must try to send a JACS-signed error about *that* failure.
            const signingFailureErrorObject = {
                jsonrpc: "2.0",
                id: mcpResponseObject.id || request.id || null, // Try to use original ID
                error: {
                    code: -32003, // Internal JACS error on server
                    message: `Internal Server Error: Failed to JACS-sign the response: ${signingError.message}`,
                    data: signingError.toString()
                }
            };
            // Try to sign this new error object.
            try {
                const signedErrorResponse = await this.jacsAgent.signResponse(signingFailureErrorObject);
                console.warn("JacsMcpServer.handle: Returning JACS-signed error about a signing failure.");
                return signedErrorResponse;
            } catch (doubleFaultError) {
                console.error("JacsMcpServer.handle: DOUBLE FAULT - Failed to even sign the error about a signing failure:", doubleFaultError);
                // Last resort: send a plain text error. The client won't be able to JACS-verify this.
                // The StreamableHTTPServerTransport will likely try to JSON.stringify this if it's not a string.
                // So, returning a string directly is safest for raw transmission.
                // Note: The client expects a JACS string. This will likely cause a verification error on client.
                return `{\"jsonrpc\":\"2.0\",\"id\":${JSON.stringify(signingFailureErrorObject.id)},\"error\":{\"code\":-32000,\"message\":\"Server double fault: Cannot JACS-sign error response: ${doubleFaultError.message}\"}}`;
            }
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
     * @param {string} options.url - Server URL
     * @param {string} [options.configPath] - Path to JACS config
     */
    constructor(options) {
        super({
            name: options.name,
            version: options.version
        });

        this.serverUrl = options.url;
        this.configPath = options.configPath;
        console.log(`JacsMcpClient Constructor: Initialized name='${options.name}', version='${options.version}\', url='${this.serverUrl}\'. Config path: \'${this.configPath}\'`);
    }

    /**
     * Connects the client to the server using the configured JACS transport.
     */
    async connect() {
        if (!this.serverUrl) {
            throw new Error("JacsMcpClient.connect: Server URL (options.url) is not configured.");
        }
        let serverUrlObject;
        try {
            serverUrlObject = new URL(this.serverUrl);
        } catch (e) {
            throw new Error(`JacsMcpClient.connect: Invalid server URL \'${this.serverUrl}\': ${e.message}`);
        }

        console.log(`JacsMcpClient.connect: Creating StreamableHTTPClientTransport for URL: ${serverUrlObject.href}`);
        const baseTransport = new StreamableHTTPClientTransport(serverUrlObject);
        
        console.log(`JacsMcpClient.connect: Wrapping base transport with JACS. Config path for JACS: \'${this.configPath}\'`);
        const jacsWrappedTransport = createJacsTransport(baseTransport, {
            configPath: this.configPath 
        });
        
        console.log("JacsMcpClient.connect: Attempting super.connect with JACS-wrapped transport...");
        await super.connect(jacsWrappedTransport);
        console.log("JacsMcpClient.connect: Successfully connected to server.");
    }
}