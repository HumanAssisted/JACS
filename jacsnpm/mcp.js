// File: JACS/jacsnpm/mcp.js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

/**
 * Creates middleware for JACS document verification and signing
 * @param {Object} options
 * @param {string} [options.configPath] - Path to JACS config file
 */
export function createJacsMiddleware(options = {}) {
    return async (ctx, next) => {
        const jacs = await import('./index.js');
        
        if (options.configPath) {
            await jacs.load(options.configPath);
        }

        // Verify incoming documents
        if (ctx.request?.params?.document) {
            const isValid = await jacs.verifyDocument(ctx.request.params.document);
            if (!isValid) {
                throw new Error('Invalid JACS document');
            }
        }

        await next();

        // Sign outgoing documents
        if (ctx.response?.result?.document) {
            ctx.response.result.document = await jacs.createDocument(
                ctx.response.result.document,
                null, null, true, null, false
            );
        }
    };
}

/**
 * Creates a transport wrapper for JACS document handling
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

        if (msg.params?.document) {
            msg.params.document = await jacs.createDocument(
                msg.params.document,
                null, null, true, null, false
            );
        }

        return originalSend(msg);
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