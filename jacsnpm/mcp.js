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
        const jacs = await import('./index.js'); // Restored dynamic import
        
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
        const jacs = await import('./index.js'); // Restored dynamic import
        
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
        
        super({
            name: options.name,
            version: options.version
        });

        this.configPath = options.configPath;
        this.explicitTransport = transportInstance;
        this.jacsAgent = null; // To store the loaded JACS agent
    }

    async loadJacsAgent() {
        if (!this.configPath) {
            console.warn("JacsMcpServer: configPath not provided, JACS agent not loaded. Signing/verification will likely fail.");
            return false; // Indicate agent not loaded
        }
        if (this.jacsAgent) {
            return true; // Already loaded
        }
        try {
            const jacs = await import('./index.js');
            // Assuming jacs.load might return the agent or a status,
            // or simply configures a global state within the jacs module.
            // For simplicity, we'll assume it configures a global state
            // and we store a reference to the jacs module itself,
            // or a specific agent object if load returns one.
            await jacs.load(this.configPath);
            this.jacsAgent = jacs; // Store reference to the jacs module after successful load
            console.log("JacsMcpServer: JACS agent loaded successfully.");
            return true;
        } catch (error) {
            console.error("JacsMcpServer: Failed to load JACS agent.", error);
            this.jacsAgent = null;
            // Re-throw or throw a specific error to halt server startup if critical
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

        // Attempt to load JACS agent before connecting the underlying MCP server
        await this.loadJacsAgent(); 
        // If loadJacsAgent throws, connect will not proceed.

        await super.connect(this.explicitTransport);
        // Note: The actual HTTP server listening is started in mcp.server.js AFTER this connect.
        // If loadJacsAgent fails, the main() in mcp.server.js would catch it.
    }

    // Override the handle method to add JACS verification
    async handle(request) {
        if (!this.jacsAgent) {
            // This case should ideally be prevented by connect() failing if agent load is critical.
            // However, as a safeguard or if agent loading was made non-critical at startup:
            console.error("JacsMcpServer: JACS agent not available for handling request. Verification/signing will be skipped or fail.");
            // Depending on policy, either throw, or proceed without JACS (unsafe), or try to load again.
            // For now, let's assume if connect succeeded, agent should be available or loading was optional.
            // If agent loading is strictly critical, an error should be thrown here.
            // For this example, let's try loading it again if it wasn't loaded.
            // This makes it behave like it did before, loading per-request if not preloaded.
            if (!this.jacsAgent) { // Check again after potential console error
                 const jacs = await import('./index.js');
                 if (this.configPath) {
                    try {
                        await jacs.load(this.configPath);
                        this.jacsAgent = jacs; // Store it for subsequent requests
                    } catch (loadError) {
                         console.error("JacsMcpServer: Failed to load JACS agent during handle.", loadError);
                         throw new Error(`Request handling failed: JACS agent could not be loaded. Original error: ${loadError.message}`);
                    }
                 } else {
                    throw new Error("Request handling failed: JACS configPath not set, agent cannot be loaded.");
                 }
            }
        }

        const verified = await this.jacsAgent.verifyRequest(request.payload);
        if (!verified) {
            throw new Error('Failed to verify request signature');
        }

        const response = await super.handle(request);

        return {
            ...response,
            payload: await this.jacsAgent.signResponse(response.payload)
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