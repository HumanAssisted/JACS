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
    transport.send = async (msg) => {
        const jacs = await import('./index.js');
        if (options.configPath) { await jacs.load(options.configPath); }

        console.log("Original MCP message:", JSON.stringify(msg, null, 2));
        
        // Don't modify the original message structure at all
        // Instead, create a wrapper for JACS
        const wrapper = { jacs_payload: msg };
        
        // Sign the entire wrapper, which will return a JWS
        const signedJWS = jacs.signRequest(wrapper);
        console.log("Signed JWS (first 50 chars):", signedJWS.substring(0, 50) + "...");
        
        // The signed JWS contains our original message wrapped in jacs_payload
        // We need to extract the payload back out and send it
        try {
            // Parse the JWS to extract the payload
            const jwsParts = signedJWS.split('.');
            if (jwsParts.length !== 3) {
                throw new Error('Invalid JWS format');
            }
            
            // Base64 decode the payload
            const payloadB64 = jwsParts[1];
            const payloadJson = Buffer.from(payloadB64, 'base64').toString('utf8');
            const payload = JSON.parse(payloadJson);
            
            // Extract the original message from jacs_payload
            if (!payload.jacs_payload) {
                throw new Error('Missing jacs_payload in decoded JWS');
            }
            
            console.log("Extracted payload from JWS:", JSON.stringify(payload.jacs_payload, null, 2));
            
            // Send the original message, unchanged
            const serverRpcResponse = await originalSend(msg);
            console.log("Server RPC Response:", JSON.stringify(serverRpcResponse, null, 2));
            
            // Handle potential JWS responses similarly
            if (serverRpcResponse.hasOwnProperty('result') && 
                typeof serverRpcResponse.result === 'string' && 
                serverRpcResponse.result.split('.').length === 3) {
                
                console.log("Result appears to be a JWS, verifying...");
                const verifiedPayload = await jacs.verifyResponse(serverRpcResponse.result);
                console.log("Verified payload:", JSON.stringify(verifiedPayload, null, 2));
                
                // Extract the actual payload content from jacs_payload if it exists
                if (verifiedPayload && verifiedPayload.jacs_payload) {
                    return {
                        ...serverRpcResponse,
                        result: verifiedPayload.jacs_payload
                    };
                }
                
                return {
                    ...serverRpcResponse,
                    result: verifiedPayload
                };
            }
            
            if (serverRpcResponse.hasOwnProperty('error') && 
                typeof serverRpcResponse.error === 'string' && 
                serverRpcResponse.error.split('.').length === 3) {
                
                console.log("Error appears to be a JWS, verifying...");
                const verifiedPayload = await jacs.verifyResponse(serverRpcResponse.error);
                console.log("Verified error payload:", JSON.stringify(verifiedPayload, null, 2));
                
                // Extract the actual payload content from jacs_payload if it exists
                if (verifiedPayload && verifiedPayload.jacs_payload) {
                    return {
                        ...serverRpcResponse,
                        error: verifiedPayload.jacs_payload
                    };
                }
                
                return {
                    ...serverRpcResponse,
                    error: verifiedPayload
                };
            }
            
            return serverRpcResponse;
            
        } catch (error) {
            console.error("Error in JACS transport:", error);
            throw new Error(`JACS transport error: ${error.message}`);
        }
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
    }

    async loadJacsAgent() {
        if (!this.configPath) {
            console.warn("JacsMcpServer: configPath not provided, JACS agent not loaded.");
            return false;
        }
        if (this.jacsAgent) return true;
        try {
            const jacs = await import('./index.js');
            await jacs.load(this.configPath);
            this.jacsAgent = jacs;
            console.log("JacsMcpServer: JACS agent loaded successfully.");
            return true;
        } catch (error) {
            console.error("JacsMcpServer: Failed to load JACS agent.", error);
            this.jacsAgent = null;
            throw new Error(`JacsMcpServer: Critical JACS agent failed to load from ${this.configPath}. Server cannot start securely. Original error: ${error.message}`);
        }
    }

    /**
     * Connects the server using the configured transport.
     */
    async connect() {
        if (!this.explicitTransport) {
            throw new Error("JacsMcpServer: Transport not initialized or configured.");
        }

        await this.loadJacsAgent();
        await super.connect(this.explicitTransport);
    }

    async handle(request) {
        if (!this.jacsAgent) {
            console.error("JacsMcpServer: JACS agent not loaded during handle. Attempting to load...");
            await this.loadJacsAgent();
            if (!this.jacsAgent) {
                 throw new Error("JacsMcpServer: JACS agent could not be loaded for handling request.");
            }
        }

        // The 'request' object here is the MCP compliant request, e.g. { jsonrpc: "2.0", id: "1", method: "...", payload: ... }
        // request.payload is the JSON-RPC request object { id: "1", method: "...", params: ... }

        console.log("JACS Server: Received raw request payload:", JSON.stringify(request.payload, null, 2));

        // Clone the request.payload to modify it for super.handle()
        const actualRpcRequestObject = JSON.parse(JSON.stringify(request.payload));
        
        // If actualRpcRequestObject.params exists and is a string (potentially a JWS)
        if (actualRpcRequestObject.params && typeof actualRpcRequestObject.params === 'string' && actualRpcRequestObject.params.split('.').length === 3) {
            console.log("JACS Server: Verifying JWS in 'params' field:", actualRpcRequestObject.params.substring(0, 50) + "...");
            const verifiedParamsWrapper = await this.jacsAgent.verifyRequest(actualRpcRequestObject.params); // verifyRequest is an alias for verifyResponse
            
            if (verifiedParamsWrapper && verifiedParamsWrapper.hasOwnProperty('jacs_payload')) {
                actualRpcRequestObject.params = verifiedParamsWrapper.jacs_payload;
                console.log("JACS Server: Unwrapped 'params' from jacs_payload:", JSON.stringify(actualRpcRequestObject.params, null, 2));
            } else {
                // This means the JWS didn't contain the expected jacs_payload structure.
                // This could be an error or a JWS not signed by our convention.
                console.error("JACS Server: 'params' JWS verification did not yield jacs_payload. Using raw verification output:", JSON.stringify(verifiedParamsWrapper, null, 2));
                actualRpcRequestObject.params = verifiedParamsWrapper; // Let SDK handle this, may fail Zod
            }
        } else if (actualRpcRequestObject.params) {
             console.log("JACS Server: 'params' field is not a JWS string, passing as is:", JSON.stringify(actualRpcRequestObject.params, null, 2));
        }


        console.log("JACS Server: Calling super.handle with processed request object:", JSON.stringify(actualRpcRequestObject, null, 2));
        const mcpResponse = await super.handle(actualRpcRequestObject);
        console.log("JACS Server: Response from super.handle:", JSON.stringify(mcpResponse, null, 2));

        const signedResponse = { 
            jsonrpc: "2.0", 
            id: mcpResponse.id 
        };

        if (mcpResponse.hasOwnProperty('error')) {
            // mcpResponse.error is the actual error object
            console.log("JACS Server: Signing 'error' object:", JSON.stringify(mcpResponse.error, null, 2));
            signedResponse.error = await this.jacsAgent.signResponse(mcpResponse.error); // signResponse wraps in jacs_payload and returns JWS
            console.log("JACS Server: 'error' object signed into JWS.");
        } else if (mcpResponse.hasOwnProperty('result')) {
            // mcpResponse.result is the actual result object
            console.log("JACS Server: Signing 'result' object:", JSON.stringify(mcpResponse.result, null, 2));
            signedResponse.result = await this.jacsAgent.signResponse(mcpResponse.result); // signResponse wraps in jacs_payload and returns JWS
            console.log("JACS Server: 'result' object signed into JWS.");
        }

        console.log("JACS Server: Final signed response to send:", JSON.stringify(signedResponse, null, 2));
        return signedResponse;
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
    }

    /**
     * Connects the client to the server using the configured JACS transport.
     */
    async connect() {
        if (!this.serverUrl) {
            throw new Error("JacsMcpClient: Server URL is not configured.");
        }

        const baseTransport = new StreamableHTTPClientTransport(this.serverUrl);
        const jacsTransport = createJacsTransport(baseTransport, {
            configPath: this.configPath
        });

        await super.connect(jacsTransport);
    }
}