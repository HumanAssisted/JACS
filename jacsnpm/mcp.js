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
        
        if (options.configPath) {
            await jacs.load(options.configPath);
        }

        // Verify incoming request
        if (ctx.request) {
            try {
                ctx.request = jacs.verifyResponse(ctx.request);
            } catch (error) {
                throw new Error(`Invalid JACS request: ${error.message}`);
            }
        }

        await next();

        // Sign outgoing response
        if (ctx.response) {
            try {
                ctx.response = jacs.signRequest(ctx.response);
            } catch (error) {
                throw new Error(`Failed to sign response: ${error.message}`);
            }
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
        
        if (options.configPath) {
            await jacs.load(options.configPath);
        }

        // Sign the entire outgoing message
        const signedMsg = jacs.signRequest(msg);
        const response = await originalSend(signedMsg);
        
        // Verify the entire response
        return jacs.verifyResponse(response);
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
        
        // Pass only name and version to McpServer constructor,
        // as transport is handled by McpServer.connect(transport)
        super({
            name: options.name,
            version: options.version
        });

        this.configPath = options.configPath;
        // Store the transport instance to be used in the connect method
        this.explicitTransport = transportInstance;
    }

    /**
     * Connects the server using the configured transport.
     */
    async connect() {
        if (!this.explicitTransport) {
            throw new Error("JacsMcpServer: Transport not initialized or configured.");
        }
        // Call the parent McpServer's connect method with the stored transport
        await super.connect(this.explicitTransport);
    }

    // Override the handle method to add JACS verification
    async handle(request) {
        const jacs = await import('./index.js');
        
        if (this.configPath) {
            await jacs.load(this.configPath);
        }

        // Verify the incoming request using JACS
        const verified = await jacs.verifyRequest(request.payload);
        if (!verified) {
            throw new Error('Failed to verify request signature');
        }

        // Call parent class to handle the request
        const response = await super.handle(request);

        // Sign the response using JACS
        return {
            ...response,
            payload: await jacs.signResponse(response.payload)
        };
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

        // Store URL and configPath for use in the connect method
        this.serverUrl = options.url;
        this.configPath = options.configPath;
        // this.transport will be initialized and passed during the connect phase
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

        // Call the parent Client's connect method with the JACS-wrapped transport
        await super.connect(jacsTransport);
    }
}