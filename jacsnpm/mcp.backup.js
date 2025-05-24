import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Server as CoreMcpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js"; // For future SSE support
import jacsNapiInstance from './index.js'; // Import the NAPI instance at the module level
import getRawBody from "raw-body"; // For JacsMcpServer SSE POST handling
import contentType from "content-type"; // For JacsMcpServer SSE POST handling

/**
 * Corrected Client-side JACS transport wrapper.
 */
export function createJacsClientTransportWrapper(rawTransport, options = {}) {
    let jacsAgent = options.jacsAgent || null; // Allow passing pre-loaded agent

    async function ensureJacsAgent() {
        if (jacsAgent) return jacsAgent;
        if (options.configPath && !jacsAgent) {
            try {
                // console.log(`JACS Client Wrapper: Loading JACS config from ${options.configPath}`);
                await jacsNapiInstance.load(options.configPath);
                jacsAgent = jacsNapiInstance;
                // console.log("JACS Client Wrapper: JACS config loaded, agent set.");
                return jacsAgent;
            } catch (e) {
                console.error(`JACS Client Wrapper: FATAL - Failed to load JACS config ${options.configPath}`, e);
                throw e;
            }
        }
        return null; 
    }

    // 1. Wrap rawTransport.send for outgoing messages
    const originalRawSend = rawTransport.send.bind(rawTransport);
    rawTransport.send = async (jsonRpcMessage) => { // SDK's Client calls this
        const currentJacsAgent = await ensureJacsAgent();
        if (!currentJacsAgent) {
            // console.log("JACS Client Wrapper (send): JACS off, sending raw JSON-RPC message.");
            return await originalRawSend(jsonRpcMessage); 
        }

        // console.log("JACS Client Wrapper (send): JACS on, signing JSON-RPC message:", jsonRpcMessage);
        try {
            // Assumes signRequest takes JSON-RPC object and returns JACS document string
            const jacsDocumentString = await currentJacsAgent.signRequest(jsonRpcMessage); 
            // console.log("JACS Client Wrapper (send): Signed to JACS Doc (first 100):", jacsDocumentString.substring(0,100));
            return await originalRawSend(jacsDocumentString); // Send JACS document string
        } catch (signingError) {
            console.error("JACS Client Wrapper (send): Error signing request:", signingError);
            throw signingError;
        }
    };

    // 2. Wrap rawTransport.onmessage for incoming messages
    let sdkClientOnMessageCallback = null;
    const onmessageDescriptor = Object.getOwnPropertyDescriptor(rawTransport, 'onmessage');

    Object.defineProperty(rawTransport, 'onmessage', {
        get: () => sdkClientOnMessageCallback,
        set: (callback) => {
            // console.log("JACS Client Wrapper: SDK's onmessage_client_callback is being set.");
            sdkClientOnMessageCallback = callback;
        },
        configurable: true, 
        enumerable: true 
    });
    
    // This is the new function that will be called by the underlying transport's internals when data arrives.
    const originalMessageHandler = onmessageDescriptor ? onmessageDescriptor.value : rawTransport.onmessage; // Keep if any existed before SDK
    rawTransport.onmessage = async (messageFromServer) => { 
        // console.log("JACS Client Wrapper (raw onmessage): Received from server (type):", typeof messageFromServer);
        const currentJacsAgent = await ensureJacsAgent();
        let messageToDeliverToSdk = messageFromServer; 

        if (currentJacsAgent && typeof messageFromServer === 'string') { // Expecting JACS doc string
            try {
                // Assumes verifyResponse takes JACS doc string and returns { payload: jsonRpcObject }
                const verificationResult = await currentJacsAgent.verifyResponse(messageFromServer); 
                messageToDeliverToSdk = verificationResult.payload; 
                // console.log("JACS Client Wrapper (raw onmessage): JACS verified server message. Payload:", messageToDeliverToSdk);
            } catch (e) {
                console.error("JACS Client Wrapper (raw onmessage): Error verifying JACS from server:", e);
                if (rawTransport.onerror) rawTransport.onerror(new Error(`JACS verification of server message failed: ${e.message}`));
                return; 
            }
        } else if (!currentJacsAgent && typeof messageFromServer === 'string') {
            try {
                messageToDeliverToSdk = JSON.parse(messageFromServer);
            } catch (e) {
                // console.warn("JACS Client Wrapper (raw onmessage): JACS off, failed to parse as JSON. Passing raw string.");
            }
        }
        
        if (sdkClientOnMessageCallback) {
            // console.log("JACS Client Wrapper (raw onmessage): Delivering to SDK's onmessage callback:", messageToDeliverToSdk);
            sdkClientOnMessageCallback(messageToDeliverToSdk);
        } else if (typeof originalMessageHandler === 'function' && originalMessageHandler !== rawTransport.onmessage) {
            // console.log("JACS Client Wrapper (raw onmessage): Delivering to original transport onmessage (if any).");
            originalMessageHandler(messageToDeliverToSdk)
        } else {
            // console.warn("JACS Client Wrapper (raw onmessage): No SDK onmessage_client_callback set. Message not delivered to SDK.");
        }
    };
    
    // Proxy other essential transport properties/methods if they are not automatically on rawTransport
    // (e.g., if createJacsClientTransportWrapper created a new object instead of mutating rawTransport).
    // Since we mutate rawTransport, `start`, `close`, `onclose`, `onerror` setters/getters need to be handled carefully.
    // `onclose` and `onerror` are handled by capturing the SDK's setters similar to `onmessage`.

    let sdkClientOnCloseCallback = null;
    const oncloseDescriptor = Object.getOwnPropertyDescriptor(rawTransport, 'onclose');
    Object.defineProperty(rawTransport, 'onclose', {
        get: () => sdkClientOnCloseCallback,
        set: (cb) => { 
            // console.log("JACS Client Wrapper: SDK's onclose_client_callback is being set.");
            sdkClientOnCloseCallback = cb;
        },
        configurable: true, enumerable: true
    });
    const originalOnCloseHandler = oncloseDescriptor ? oncloseDescriptor.value : rawTransport.onclose;
    rawTransport.onclose = () => {
        // console.log("JACS Client Wrapper (raw onclose): Triggered.");
        if (sdkClientOnCloseCallback) sdkClientOnCloseCallback();
        else if (typeof originalOnCloseHandler === 'function' && originalOnCloseHandler !== rawTransport.onclose) originalOnCloseHandler();
    };

    let sdkClientOnErrorCallback = null;
    const onerrorDescriptor = Object.getOwnPropertyDescriptor(rawTransport, 'onerror');
    Object.defineProperty(rawTransport, 'onerror', {
        get: () => sdkClientOnErrorCallback,
        set: (cb) => {
            // console.log("JACS Client Wrapper: SDK's onerror_client_callback is being set.");
            sdkClientOnErrorCallback = cb;
        },
        configurable: true, enumerable: true
    });
    const originalOnErrorHandler = onerrorDescriptor ? onerrorDescriptor.value : rawTransport.onerror;
    rawTransport.onerror = (err) => {
        // console.error("JACS Client Wrapper (raw onerror): Triggered:", err);
        if (sdkClientOnErrorCallback) sdkClientOnErrorCallback(err);
        else if (typeof originalOnErrorHandler === 'function' && originalOnErrorHandler !== rawTransport.onerror) originalOnErrorHandler(err);
    };

    return rawTransport;
}

/**
 * Server-side JACS transport wrapper.
 */
function createJacsServerTransportWrapper(rawTransport, jacsAgentInstance) {
    const wrappedTransport = {
        // Store reference to the raw transport for direct access
        _rawSseTransport: rawTransport
    }; 
    let sdkServerOnMessageCallback = null;

    const jacsProcessingOnMessage = async (jacsDocumentStringFromClient) => {
        if (!jacsAgentInstance) { // JACS security is off
            try {
                // For JACS off, just parse the JSON normally
                const plainJson = JSON.parse(jacsDocumentStringFromClient);
                if (sdkServerOnMessageCallback) {
                    sdkServerOnMessageCallback(plainJson);
                } else {
                    console.error("JACS Server Wrapper (jacsProcessingOnMessage - JACS OFF): sdkServerOnMessageCallback NOT SET!");
                }
            } catch (e) {
                console.error("JACS Server Wrapper (jacsProcessingOnMessage - JACS OFF): Failed to parse as JSON:", e);
                if (rawTransport.onerror) rawTransport.onerror(new Error("Invalid JSON message received"));
            }
            return;
        }

        // JACS security is ON
        if (typeof jacsDocumentStringFromClient !== 'string') {
            console.error("JACS Server Wrapper (jacsProcessingOnMessage - JACS ON): Expected string, got:", typeof jacsDocumentStringFromClient);
            if (rawTransport.onerror) rawTransport.onerror(new Error("Invalid message format: Expected string."));
            return;
        }

        try {
            // The string we receive is actually a JSON-stringified string
            // We need to parse it first to get the actual JACS document string
            const actualJacsDocument = JSON.parse(jacsDocumentStringFromClient);
            
            console.log("JACS Server Wrapper: Parsed document type:", typeof actualJacsDocument);
            
            // Now pass the actual JACS document string to verification
            const verificationResult = await jacsAgentInstance.verifyResponse(actualJacsDocument);
            const jsonRpcRequest = verificationResult.payload;
            
            if (sdkServerOnMessageCallback) {
                sdkServerOnMessageCallback(jsonRpcRequest);
            } else {
                console.error("JACS Server Wrapper: SDK callback not set, message not delivered");
            }
        } catch (error) {
            console.error("JACS Server Wrapper: JACS verification failed:", error);
            // Rest of error handling...
            throw error;
        }
    };

    Object.defineProperty(wrappedTransport, 'onmessage', {
        get: () => sdkServerOnMessageCallback,
        set: (callback) => {
            sdkServerOnMessageCallback = callback; 
        },
        configurable: true, enumerable: true
    });

    wrappedTransport.processMessageWithJacs = jacsProcessingOnMessage;

    const originalRawServerSend = rawTransport.send.bind(rawTransport);
    wrappedTransport.send = async (jsonRpcResponseFromServer) => {
        if (!jacsAgentInstance) { // JACS OFF
            // When JACS is off, the originalRawServerSend (e.g. SSEServerTransport.send)
            // might expect an object or a stringified object depending on its implementation.
            // McpServer usually sends an object to the transport.send.
            return await originalRawServerSend(jsonRpcResponseFromServer); 
        }
        // JACS ON
        try {
            const jacsDocumentStringForResponse = await jacsAgentInstance.signRequest(jsonRpcResponseFromServer);
            // originalRawServerSend here is the raw transport's send (e.g. SSEServerTransport)
            // which should handle the string appropriately (e.g. SSEServerTransport stringifies its input if it's an object,
            // but if it receives a string, it might send it as is or wrap it further in an event).
            // Given JACS document is already a string, it should be passed directly.
            return await originalRawServerSend(jacsDocumentStringForResponse);
        } catch (error) {
            console.error("JACS Server Wrapper (send - JACS ON): Error signing JACS response:", error);
            throw error; 
        }
    };
    
    // Forward close handling
    let sdkServerOnCloseCallback = null;
    Object.defineProperty(wrappedTransport, 'onclose', {
        get: () => sdkServerOnCloseCallback,
        set: (cb) => { sdkServerOnCloseCallback = cb; },
        configurable: true, enumerable: true
    });
    const originalRawOnClose = rawTransport.onclose;
    rawTransport.onclose = () => {
        if(typeof originalRawOnClose === 'function') originalRawOnClose.call(rawTransport);
        if (sdkServerOnCloseCallback) sdkServerOnCloseCallback();
    };
    if (typeof rawTransport.close === 'function') {
        wrappedTransport.close = () => {
            return rawTransport.close();
        };
    }

    // Forward error handling
    let sdkServerOnErrorCallback = null;
    Object.defineProperty(wrappedTransport, 'onerror', {
        get: () => sdkServerOnErrorCallback,
        set: (cb) => { sdkServerOnErrorCallback = cb; },
        configurable: true, enumerable: true
    });
    const originalRawOnError = rawTransport.onerror;
    rawTransport.onerror = (error) => {
        if(typeof originalRawOnError === 'function') originalRawOnError.call(rawTransport, error);
        if (sdkServerOnErrorCallback) sdkServerOnErrorCallback(error);
    };

    // Forward start if it exists
    if (typeof rawTransport.start === 'function') {
        wrappedTransport.start = rawTransport.start.bind(rawTransport);
    }
    
    // Forward sessionId if it exists
    if (Object.prototype.hasOwnProperty.call(rawTransport, 'sessionId')) {
      Object.defineProperty(wrappedTransport, 'sessionId', {
        get: () => rawTransport.sessionId,
        enumerable: true, configurable: false,
      });
    }

    return wrappedTransport;
}

export class JacsMcpServer extends McpServer {
    constructor(options) {
        super(
            { name: options.name, version: options.version },
            options.serverOptions 
        );
        this.configPath = options.configPath;
        this.jacsAgent = null; 
        this.transportType = options.transportType || (options.sseConfig ? 'sse' : 'stdio');
        // console.log(`JacsMcpServer Constructor: Initialized. ConfigPath: '${this.configPath}', Type: ${this.transportType}`);

        if (this.transportType === 'sse') {
            this.sseConfig = options.sseConfig || {};
            this.activeSseTransports = new Map(); // Stores wrapped transports
            // console.log("JacsMcpServer: Configured for SSE transport.");
        } else { // stdio or custom
            this.rawTransport = options.transport || new StdioServerTransport();
        }
    }

    async loadJacsAgent() {
        // Skip if already loaded
        if (this.jacsAgent) {
            console.log("JacsMcpServer: JACS agent already loaded, skipping reload");
            return this.jacsAgent;
        }

        if (this.configPath) {
            try {
                console.log(`JacsMcpServer: Loading JACS agent from ${this.configPath}`);
                await jacsNapiInstance.load(this.configPath);
                this.jacsAgent = jacsNapiInstance;
                return this.jacsAgent;
            } catch (e) {
                console.error("JacsMcpServer: Failed to load JACS agent:", e);
                throw e;
            }
        }
        return null;
    }

    async connect(transportOverride = null) {
        console.log(`JacsMcpServer.connect: Called. transportType: ${this.transportType}, transportOverride: ${transportOverride ? 'present' : 'absent'}`);
        let agentLoadedSuccessfully = false;
        if (this.configPath) {
            try {
                await this.loadJacsAgent(); 
                agentLoadedSuccessfully = !!this.jacsAgent;
            } catch (e) {
                console.error("JacsMcpServer.connect: JACS agent failed to load (critical error thrown). Aborting.", e.message);
                throw e;
            }
        } else {
            console.warn("JacsMcpServer.connect: No JACS configPath. JACS security bypassed. this.jacsAgent will be null.");
        }
        
        if (this.transportType === 'sse' && !transportOverride) {
            console.log("JacsMcpServer.connect: SSE mode without transportOverride. Server core initialized (JACS, routes). Dynamic transports will be handled separately.");
            return; 
        }

        const currentRawTransport = transportOverride || this.rawTransport;
        if (!currentRawTransport) {
            console.error("JacsMcpServer.connect: Transport is undefined and not in SSE dynamic mode without override.");
            throw new Error("JacsMcpServer.connect: Transport is undefined.");
        }

        let transportToConnect;
        if (this.jacsAgent) {
            console.log("JacsMcpServer.connect: JACS agent active. Wrapping transport.");
            transportToConnect = createJacsServerTransportWrapper(currentRawTransport, this.jacsAgent);
        } else {
            console.warn("JacsMcpServer.connect: JACS agent not active (null). Using raw transport.");
            transportToConnect = currentRawTransport;
        }
        
        console.log("JacsMcpServer.connect: Calling super.connect() with the transport.");
        try {
            await super.connect(transportToConnect);
        } catch (error) {
            console.error("JacsMcpServer.connect: Error during super.connect() with transport:", error);
            throw error;
        }
        console.log("JacsMcpServer.connect: super.connect() completed for the provided transport.");
    }
    
    async handleSseRequest(req, res) {
        if (this.transportType !== 'sse' || !this.sseConfig) {
            res.writeHead(500).end("Server not configured for SSE.");
            return;
        }

        const ssePostEndpoint = this.sseConfig.postEndpoint || '/mcp-sse-post';
        const rawSseTransport = new SSEServerTransport(ssePostEndpoint, res);
        
        let jacsAgentForSse = null;
        if (this.configPath) {
            try {
                if (await this.loadJacsAgent()) {
                    jacsAgentForSse = this.jacsAgent;
                }
            } catch(e) {
                console.error("JacsMcpServer (SSE GET): Failed to load JACS agent for SSE connection.", e);
                res.writeHead(500).end("Internal server error during JACS setup for SSE.");
                return;
            }
        }
        
        const transportForThisSseClient = jacsAgentForSse 
            ? createJacsServerTransportWrapper(rawSseTransport, jacsAgentForSse)
            : rawSseTransport;

        try {
            // Connect this transport to the server
            // Note: connect() will call start() automatically, so we don't need to call it ourselves
            await super.connect(transportForThisSseClient);
            
            this.activeSseTransports.set(rawSseTransport.sessionId, transportForThisSseClient);

            req.on('close', () => {
                transportForThisSseClient.close();
                this.activeSseTransports.delete(rawSseTransport.sessionId);
            });

        } catch (error) {
            console.error("JacsMcpServer (SSE GET): Error starting SSE transport:", error);
            // Only try to send headers if they haven't been sent already
            if (!res.headersSent) {
                res.writeHead(500).end("Failed to establish SSE connection with MCP server.");
            }
        }
    }

    async handleSsePost(req, res) {
        if (this.transportType !== 'sse' || !this.activeSseTransports) {
            res.writeHead(400).end("Server not configured for SSE POSTs or no active transports.");
            return;
        }
    
        const url = new URL(req.url, `http://${req.headers.host}`);
        const sessionIdFromQuery = url.searchParams.get('sessionId');
    
        if (!sessionIdFromQuery) {
            res.writeHead(400).end("Missing sessionId in POST request query.");
            return;
        }
        
        const activeWrappedTransport = this.activeSseTransports.get(sessionIdFromQuery);
        if (!activeWrappedTransport) {
            console.error(`JacsMcpServer (SSE POST): No active transport for sessionId: ${sessionIdFromQuery}`);
            res.writeHead(404).end(`No active SSE session for ID ${sessionIdFromQuery}`);
            return;
        }
        
        let rawBodyString;
        try {
            const rawBodyBuffer = await getRawBody(req, {
                limit: '4mb',
                encoding: contentType.parse(req.headers["content-type"] ?? "application/json").parameters.charset ?? "utf-8",
            });
            rawBodyString = rawBodyBuffer.toString();
        } catch (error) {
            console.error("JacsMcpServer (SSE POST): Error reading raw body:", error);
            res.writeHead(400).end("Failed to read request body.");
            return;
        }
    
        try {
            // If we have JACS enabled and we're using a wrapped transport with processMessageWithJacs
            if (this.jacsAgent && typeof activeWrappedTransport.processMessageWithJacs === 'function') {
                // Use our JACS processing method which handles string input
                await activeWrappedTransport.processMessageWithJacs(rawBodyString);
            } 
            // Otherwise, if we're using the standard SDK transport
            else if (activeWrappedTransport._rawSseTransport && 
                     typeof activeWrappedTransport._rawSseTransport.handleMessage === 'function') {
                // Parse the JSON string into an object before passing to handleMessage
                const jsonObject = JSON.parse(rawBodyString);
                await activeWrappedTransport._rawSseTransport.handleMessage(jsonObject);
            } 
            // Fall back to trying handleMessage on the wrapped transport
            else if (typeof activeWrappedTransport.handleMessage === 'function') {
                // Parse the JSON string into an object before passing to handleMessage
                const jsonObject = JSON.parse(rawBodyString);
                await activeWrappedTransport.handleMessage(jsonObject);
            }
            // If none of the above methods are available
            else {
                throw new Error("No suitable message handling method found on the transport");
            }
            
            if (!res.writableEnded) {
               res.writeHead(202).end("Accepted"); 
            }
        } catch (processingError) { 
            console.error("JacsMcpServer (SSE POST): Error processing message:", processingError);
            if (!res.writableEnded) {
                res.writeHead(500).end("Error processing message.");
            }
        }
    }
}

export class JacsMcpClient extends Client {
    #jacsAgent = null;
    #configPath = null;

    constructor(options) {
        super(
            { name: options.name, version: options.version },
            options.clientOptions 
        );

        this.transportType = options.transportType || 'stdio';
        this.clientOptions = options; 
        this.#configPath = options.configPath;
        // console.log(`JacsMcpClient Constructor: Type='${this.transportType}'. ConfigPath='${this.#configPath}'`);
    }

    async loadJacsAgent() {
        if (this.#jacsAgent) return true;
        if (!this.#configPath) {
            // console.warn("JacsMcpClient.loadJacsAgent: configPath not provided. JACS bypassed for client.");
            return false; 
        }
        // console.log(`JacsMcpClient.loadJacsAgent: Loading JACS NAPI from '${this.#configPath}'`);
        try {
            await jacsNapiInstance.load(this.#configPath);
            this.#jacsAgent = jacsNapiInstance;
            // console.log("JacsMcpClient.loadJacsAgent: JACS NAPI instance configured.");
            return true;
        } catch (error) {
            console.error(`JacsMcpClient.loadJacsAgent: FAILED to load JACS agent from ${this.#configPath}.`, error);
            this.#jacsAgent = null;
            throw error; 
        }
    }

    async connect(transportOverride = null) {
        console.log("[JacsMcpClient.connect] Entered. transportOverride initial value:", transportOverride);
        console.log("[JacsMcpClient.connect] typeof transportOverride:", typeof transportOverride);
        if (transportOverride && typeof transportOverride.send === 'function') {
            console.log("[JacsMcpClient.connect] transportOverride appears to be a valid transport object.");
        } else {
            console.warn("[JacsMcpClient.connect] transportOverride is NULL or NOT a valid transport object initially. Value:", transportOverride);
        }

        await this.loadJacsAgent();
        let transportToUse = transportOverride;

        console.log("[JacsMcpClient.connect] transportToUse after assignment from transportOverride:", transportToUse);

        if (!transportToUse) {
            console.error("[JacsMcpClient.connect] Condition (!transportToUse) is TRUE. Entering block to create StdioClientTransport.");
            
            const { command, args, stdioEnv, stdioCwd } = this.clientOptions;
            
            if (!command || !args) {
                 console.error(`[JacsMcpClient.connect] Inside Stdio block: Missing command ('${command}') or args ('${args ? args.join(',') : 'undefined'}') for Stdio.`);
                 throw new Error("JacsMcpClient: 'command' and 'args' required for Stdio transport.");
            }
            transportToUse = new StdioClientTransport({ command, args, env: stdioEnv, cwd: stdioCwd });
        } else {
            console.log("[JacsMcpClient.connect] Condition (!transportToUse) is FALSE. Skipping StdioClientTransport creation.");
        }
        
        const jacsWrapperOptions = {
            jacsAgent: this.#jacsAgent,
            configPath: this.#configPath
        };
        // console.log("[JacsMcpClient.connect] Options for JACS wrapper:", jacsWrapperOptions); // Keep this if you want to see the values
        const jacsWrappedTransport = createJacsClientTransportWrapper(transportToUse, jacsWrapperOptions);

        try {
            await super.connect(jacsWrappedTransport);
        } catch (error) {
            console.error("[JacsMcpClient.connect] Error during super.connect:", error);
            throw error;
        }
    }

    isConnected() {
        return !!this.transport; 
    }

    async close() {
        if (this.transport) {
            // console.log("JacsMcpClient.close: Closing client transport.");
            await this.transport.close();
        }
    }
}