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

        const signedRequestJws = jacs.signRequest(msg);
        
        const serverRpcResponse = await originalSend(signedRequestJws);

        let jwsToVerify;
        let responseFieldIsError = false;

        if (serverRpcResponse.hasOwnProperty('result')) {
            jwsToVerify = serverRpcResponse.result;
        } else if (serverRpcResponse.hasOwnProperty('error')) {
            if (typeof serverRpcResponse.error === 'string' && serverRpcResponse.error.split('.').length === 3) {
                jwsToVerify = serverRpcResponse.error;
                responseFieldIsError = true;
            } else {
                return serverRpcResponse;
            }
        } else {
            throw new Error('Client: Server response missing "result" or "error" field.');
        }
        
        if (typeof jwsToVerify !== 'string') {
            throw new Error(`Client: Expected JWS string in server response's "${responseFieldIsError ? 'error' : 'result'}" field, got ${typeof jwsToVerify}`);
        }

        const verifiedPayload = await jacs.verifyResponse(jwsToVerify);

        if (responseFieldIsError) {
            return { ...serverRpcResponse, error: verifiedPayload };
        } else {
            return { ...serverRpcResponse, result: verifiedPayload };
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

        const actualRpcRequestObject = await this.jacsAgent.verifyRequest(request.payload);
        
        if (!actualRpcRequestObject || typeof actualRpcRequestObject !== 'object') {
            console.error("JacsMcpServer: verifyRequest did not return an object. Received:", actualRpcRequestObject);
            throw new Error('JACS verification failed or did not return a valid RPC request object.');
        }

        const mcpResponse = await super.handle(actualRpcRequestObject);

        let payloadToSign;
        let responseIsError = mcpResponse.hasOwnProperty('error');

        if (responseIsError) {
            payloadToSign = mcpResponse.error;
        } else {
            payloadToSign = mcpResponse.result;
        }

        const signedPayloadJws = await this.jacsAgent.signResponse(payloadToSign);

        if (responseIsError) {
            return { jsonrpc: "2.0", id: mcpResponse.id, error: signedPayloadJws };
        } else {
            return { jsonrpc: "2.0", id: mcpResponse.id, result: signedPayloadJws };
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