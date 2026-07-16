import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { JacsAgent } from './index.js';
import { JacsClient } from './client.js';
/** Reserved JSON-RPC notification carrying one serialized JACS envelope. */
export declare const JACS_MCP_SIGNED_CARRIER_METHOD = "notifications/jacs/signed";
/** Wire version for the reserved signed-envelope carrier. */
export declare const JACS_MCP_SIGNED_CARRIER_VERSION = 1;
/**
 * JACS Transport Proxy - Wraps any MCP transport with JACS signing/verification.
 *
 * Outgoing messages are signed with `signRequest()`.
 * Incoming messages are verified with `verifyResponseWithAgentId()` and are
 * dispatched only when the authenticated signer matches the configured peer
 * identity policy.
 *
 * Security defaults:
 * - local-only transport enforcement (`stdio` or loopback URL)
 * - fail-closed on signing/verification errors
 * - fail-closed until an expected/allowed peer signer is configured
 * - randomized, one-use wire IDs for request/response correlation
 *
 * Local-only mode is mandatory and cannot be disabled.
 *
 * Optional fallback behavior:
 * - `allowUnsignedFallback: true` (or `JACS_MCP_ALLOW_UNSIGNED_FALLBACK=true`)
 */
export declare class JACSTransportProxy implements Transport {
    private transport;
    private nativeAgent;
    private proxyId;
    private debug;
    private allowUnsignedFallback;
    private peerIdentityPolicy;
    private pendingRequests;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onmessage?: (message: JSONRPCMessage) => void;
    /**
     * Local/security policy options for MCP transport proxy behavior.
     */
    static readonly DEFAULT_LOCAL_ONLY = true;
    constructor(transport: Transport, clientOrAgent: JacsClient | JacsAgent, role?: "client" | "server", options?: JACSTransportProxyOptions);
    start(): Promise<void>;
    close(): Promise<void>;
    send(message: JSONRPCMessage): Promise<void>;
    get sessionId(): string | undefined;
    private cleanupExpiredPendingRequests;
    private prepareOutgoingMessage;
    private rollbackPendingRequest;
    private restoreCorrelatedResponse;
    private verifySignedEnvelope;
    private handleIncoming;
    /**
     * Removes null and undefined values from JSON objects to prevent MCP schema
     * validation failures with strict validators.
     *
     * Workaround for:
     * - https://github.com/modelcontextprotocol/typescript-sdk/issues/400
     * - https://github.com/anthropics/claude-code/issues/586
     * - https://github.com/agno-agi/agno/issues/2791
     */
    removeNullValues(obj: any): any;
}
export interface JACSTransportProxyOptions {
    /**
     * Reserved for compatibility. Local-only mode is always enforced.
     * Passing false throws an error.
     */
    localOnly?: boolean;
    /**
     * Allow fallback to unsigned/plain MCP messages when JACS signing or
     * verification fails, including parsed JSON-RPC objects that no longer carry
     * a verifiable serialized JACS envelope. Default: false (fail closed).
     */
    allowUnsignedFallback?: boolean;
    /**
     * Exact JACS agent ID expected to sign every incoming authenticated message.
     * This is the recommended endpoint-identity policy for one peer.
     */
    expectedPeerAgentId?: string;
    /**
     * Exact allowlist of JACS agent IDs permitted to sign incoming messages.
     * Use this only when one transport intentionally serves multiple peers.
     */
    allowedPeerAgentIds?: readonly string[];
    /**
     * Optional exact authenticated `jacsSignature.publicKeyHash` pin. It can be
     * used only with `expectedPeerAgentId`.
     */
    expectedPeerPublicKeyHash?: string;
    /**
     * Dangerous compatibility mode: accept any cryptographically valid signer
     * resolvable by the local JACS agent. This proves key possession only and
     * does not authenticate the intended MCP endpoint. Must be literal `true`.
     */
    dangerouslyAllowAnyValidSigner?: boolean;
}
/**
 * Create a transport proxy from a pre-loaded JacsClient or JacsAgent.
 */
export declare function createJACSTransportProxy(transport: Transport, clientOrAgent: JacsClient | JacsAgent, role?: "client" | "server", options?: JACSTransportProxyOptions): JACSTransportProxy;
/**
 * Create a transport proxy by loading a JACS agent from a config file.
 * Awaits agent loading before returning, so the proxy is immediately usable.
 */
export declare function createJACSTransportProxyAsync(transport: Transport, configPath: string, role?: "client" | "server", options?: JACSTransportProxyOptions): Promise<JACSTransportProxy>;
/** MCP tool definition shape (matches @modelcontextprotocol/sdk Tool type). */
export interface JacsMcpToolDef {
    name: string;
    description: string;
    inputSchema: {
        type: 'object';
        properties: Record<string, any>;
        required?: string[];
    };
}
/**
 * Returns the Node.js MCP compatibility tool definitions.
 *
 * The canonical full MCP contract lives in the Rust `jacs-mcp` crate. This
 * helper exposes the subset and compatibility aliases supported by jacsnpm.
 */
export declare function getJacsMcpToolDefinitions(): JacsMcpToolDef[];
/**
 * Handle a JACS MCP tool call. Returns a JSON string result.
 *
 * Use this with `server.setRequestHandler(CallToolRequestSchema, ...)`.
 */
export declare function handleJacsMcpToolCall(client: JacsClient, toolName: string, args: Record<string, any>): Promise<{
    content: Array<{
        type: 'text';
        text: string;
    }>;
}>;
/**
 * Register all JACS tools on an MCP Server instance.
 *
 * Call this once during server setup to add JACS signing, verification,
 * agreements, trust, and registry integration tools.
 *
 * @example
 * ```typescript
 * import { Server } from '@modelcontextprotocol/sdk/server/index.js';
 * import { JacsClient } from '@hai.ai/jacs/client';
 * import { registerJacsTools } from '@hai.ai/jacs/mcp';
 *
 * const server = new Server(
 *   { name: 'my-server', version: '1.0.0' },
 *   { capabilities: { tools: {} } },
 * );
 * const client = await JacsClient.quickstart({
 *   name: 'mcp-agent',
 *   domain: 'mcp.local',
 * });
 * registerJacsTools(server, client);
 * ```
 */
export declare function registerJacsTools(server: any, client: JacsClient): void;
