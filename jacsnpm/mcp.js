// File: JACS/jacsnpm/mcp.js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

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
     */
    constructor(options) {
        super({
            name: options.name,
            version: options.version
        });
        
        this.use(createJacsMiddleware({
            configPath: options.configPath
        }));
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

        const baseTransport = new StreamableHTTPClientTransport(options.url);
        this.transport = createJacsTransport(baseTransport, {
            configPath: options.configPath
        });
    }
}