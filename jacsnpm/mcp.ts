// JACS MCP — Transport proxy + full tool suite for Node.js MCP servers
//
// Two integration patterns:
//
// 1. Transport proxy: wrap any MCP transport with JACS signing/verification.
//    `createJACSTransportProxy(transport, client)`
//
// 2. Tool registration: expose JACS operations as MCP tools in your server.
//    `registerJacsTools(server, client)`
//
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { JacsAgent, fetchRemoteKey } from './index.js';
import { JacsClient } from './client.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const isStdioTransport = (transport: any): boolean => {
  return transport.constructor.name === 'StdioServerTransport' ||
         transport.constructor.name === 'StdioClientTransport';
};

function debugLog(proxyId: string, enabled: boolean, ...args: any[]): void {
  if (enabled) console.error(`[${proxyId}]`, ...args);
}

/**
 * Extract the native JacsAgent from either a JacsAgent or JacsClient instance.
 * JacsClient stores its native agent in a private `agent` field.
 */
function extractNativeAgent(clientOrAgent: JacsClient | JacsAgent): JacsAgent {
  if (clientOrAgent instanceof JacsAgent) {
    return clientOrAgent;
  }
  // JacsClient - access the private native agent at runtime
  const native = (clientOrAgent as any).agent as JacsAgent | null;
  if (!native) {
    throw new Error(
      'JacsClient has no loaded agent. Call quickstart(), ephemeral(), load(), or create() before wrapping with JACSTransportProxy.'
    );
  }
  return native;
}

// ---------------------------------------------------------------------------
// JACSTransportProxy
// ---------------------------------------------------------------------------

/**
 * JACS Transport Proxy - Wraps any MCP transport with JACS signing/verification.
 *
 * Outgoing messages are signed with `signRequest()`.
 * Incoming messages are verified with `verifyResponse()`, falling back to
 * plain JSON if verification fails (the message was not JACS-signed).
 */
export class JACSTransportProxy implements Transport {
  private nativeAgent: JacsAgent;
  private proxyId: string;
  private debug: boolean;

  // MCP SDK sets these
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(
    private transport: Transport,
    clientOrAgent: JacsClient | JacsAgent,
    role: "client" | "server" = "server",
  ) {
    this.nativeAgent = extractNativeAgent(clientOrAgent);
    this.proxyId = `JACS_${role.toUpperCase()}_PROXY`;

    const suppressDebugForStdio = isStdioTransport(transport);
    this.debug = process.env.JACS_MCP_DEBUG === 'true' && !suppressDebugForStdio;

    // Intercept incoming messages from the wrapped transport
    this.transport.onmessage = (incomingData: any) => {
      this.handleIncoming(incomingData);
    };

    // Forward transport lifecycle events
    this.transport.onclose = () => {
      if (this.onclose) this.onclose();
    };
    this.transport.onerror = (error: Error) => {
      console.error(`[${this.proxyId}] Transport error:`, error);
      if (this.onerror) this.onerror(error);
    };
  }

  // -------------------------------------------------------------------------
  // Transport interface
  // -------------------------------------------------------------------------

  async start(): Promise<void> {
    return this.transport.start();
  }

  async close(): Promise<void> {
    return this.transport.close();
  }

  async send(message: JSONRPCMessage): Promise<void> {
    // Skip signing for error responses
    if ('error' in message) {
      debugLog(this.proxyId, this.debug, 'OUTGOING: error response, skipping signing');
      await this.transport.send(message);
      return;
    }

    try {
      // Clean null params before signing (MCP SDK sometimes sends null params)
      const cleanMessage = { ...message };
      if ('params' in cleanMessage && cleanMessage.params === null) {
        delete cleanMessage.params;
      }

      debugLog(this.proxyId, this.debug, 'OUTGOING: signing message');
      const signed = this.nativeAgent.signRequest(cleanMessage);
      await this.transport.send(signed as any);
    } catch (signError) {
      console.error(`[${this.proxyId}] Signing failed, sending plain message:`, signError);
      await this.transport.send(message);
    }
  }

  get sessionId(): string | undefined {
    return (this.transport as any).sessionId;
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private handleIncoming(incomingData: string | JSONRPCMessage | object): void {
    try {
      let messageForSDK: JSONRPCMessage;

      if (typeof incomingData === 'string') {
        // Try JACS verification first
        try {
          debugLog(this.proxyId, this.debug, 'INCOMING: attempting JACS verification');
          const result = this.nativeAgent.verifyResponse(incomingData);
          messageForSDK = (result && typeof result === 'object' && 'payload' in result)
            ? (result as any).payload as JSONRPCMessage
            : result as JSONRPCMessage;
        } catch {
          // Not a JACS artifact, parse as plain JSON
          debugLog(this.proxyId, this.debug, 'INCOMING: not a JACS artifact, parsing as plain JSON');
          messageForSDK = JSON.parse(incomingData) as JSONRPCMessage;
        }
      } else if (typeof incomingData === 'object' && incomingData !== null && 'jsonrpc' in incomingData) {
        messageForSDK = incomingData as JSONRPCMessage;
      } else {
        throw new Error(`Unexpected incoming data type: ${typeof incomingData}`);
      }

      if (this.onmessage) {
        this.onmessage(messageForSDK);
      }
    } catch (error) {
      console.error(`[${this.proxyId}] Error processing incoming message:`, error);
      if (this.onerror) this.onerror(error as Error);
    }
  }

  /**
   * Removes null and undefined values from JSON objects to prevent MCP schema
   * validation failures with strict validators.
   *
   * Workaround for:
   * - https://github.com/modelcontextprotocol/typescript-sdk/issues/400
   * - https://github.com/anthropics/claude-code/issues/586
   * - https://github.com/agno-agi/agno/issues/2791
   */
  removeNullValues(obj: any): any {
    if (obj === null || obj === undefined) return undefined;
    if (typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(item => this.removeNullValues(item));

    const cleaned: any = {};
    for (const [key, value] of Object.entries(obj)) {
      const cleanedValue = this.removeNullValues(value);
      if (cleanedValue !== null && cleanedValue !== undefined) {
        cleaned[key] = cleanedValue;
      }
    }
    return cleaned;
  }
}

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

/**
 * Create a transport proxy from a pre-loaded JacsClient or JacsAgent.
 */
export function createJACSTransportProxy(
  transport: Transport,
  clientOrAgent: JacsClient | JacsAgent,
  role: "client" | "server" = "server",
): JACSTransportProxy {
  return new JACSTransportProxy(transport, clientOrAgent, role);
}

/**
 * Create a transport proxy by loading a JACS agent from a config file.
 * Awaits agent loading before returning, so the proxy is immediately usable.
 */
export async function createJACSTransportProxyAsync(
  transport: Transport,
  configPath: string,
  role: "client" | "server" = "server",
): Promise<JACSTransportProxy> {
  const agent = new JacsAgent();
  await agent.load(configPath);
  return new JACSTransportProxy(transport, agent, role);
}

// ---------------------------------------------------------------------------
// MCP Tool Definitions — mirrors the Rust jacs-mcp tool suite
// ---------------------------------------------------------------------------

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
 * Returns the full list of JACS MCP tool definitions.
 *
 * Use this with `server.setRequestHandler(ListToolsRequestSchema, ...)` to
 * advertise JACS tools from a Node.js MCP server.
 */
export function getJacsMcpToolDefinitions(): JacsMcpToolDef[] {
  return [
    {
      name: 'jacs_sign_document',
      description: 'Sign arbitrary JSON data with JACS cryptographic provenance.',
      inputSchema: {
        type: 'object',
        properties: {
          data: { type: 'string', description: 'JSON string of data to sign' },
        },
        required: ['data'],
      },
    },
    {
      name: 'jacs_verify_document',
      description: 'Verify a JACS-signed document. Returns validity, signer, and errors.',
      inputSchema: {
        type: 'object',
        properties: {
          document: { type: 'string', description: 'The signed JSON document to verify' },
        },
        required: ['document'],
      },
    },
    {
      name: 'jacs_verify_by_id',
      description: 'Verify a document by its storage ID (uuid:version format).',
      inputSchema: {
        type: 'object',
        properties: {
          document_id: { type: 'string', description: 'Document ID in uuid:version format' },
        },
        required: ['document_id'],
      },
    },
    {
      name: 'jacs_create_agreement',
      description: 'Create a multi-party agreement requiring signatures from specified agents.',
      inputSchema: {
        type: 'object',
        properties: {
          document: { type: 'string', description: 'JSON string of document to agree on' },
          agent_ids: { type: 'array', items: { type: 'string' }, description: 'Agent IDs who must sign' },
          question: { type: 'string', description: 'Question or prompt for signers' },
          timeout: { type: 'string', description: 'ISO 8601 deadline' },
          quorum: { type: 'number', description: 'Minimum signatures required (M-of-N)' },
        },
        required: ['document', 'agent_ids'],
      },
    },
    {
      name: 'jacs_sign_agreement',
      description: 'Sign an existing multi-party agreement.',
      inputSchema: {
        type: 'object',
        properties: {
          document: { type: 'string', description: 'The agreement document to sign' },
        },
        required: ['document'],
      },
    },
    {
      name: 'jacs_check_agreement',
      description: 'Check the status of a multi-party agreement.',
      inputSchema: {
        type: 'object',
        properties: {
          document: { type: 'string', description: 'The agreement document to check' },
        },
        required: ['document'],
      },
    },
    {
      name: 'jacs_audit',
      description: 'Run a JACS security audit on documents and keys.',
      inputSchema: {
        type: 'object',
        properties: {
          recent_n: { type: 'number', description: 'Number of recent documents to audit' },
        },
      },
    },
    {
      name: 'jacs_sign_file',
      description: 'Sign a file with JACS. Optionally embed the file content.',
      inputSchema: {
        type: 'object',
        properties: {
          file_path: { type: 'string', description: 'Path to the file to sign' },
          embed: { type: 'boolean', description: 'Embed file content in the document (default false)' },
        },
        required: ['file_path'],
      },
    },
    {
      name: 'jacs_verify_self',
      description: "Verify this agent's own cryptographic integrity.",
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_agent_info',
      description: 'Get the current agent ID, name, and diagnostics.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'fetch_agent_key',
      description: "Fetch an agent's public key from HAI's key distribution service.",
      inputSchema: {
        type: 'object',
        properties: {
          agent_id: { type: 'string', description: 'Agent ID (UUID format)' },
          version: { type: 'string', description: "Key version or 'latest'" },
        },
        required: ['agent_id'],
      },
    },
    {
      name: 'jacs_register',
      description: 'Register this agent with HAI.ai for cross-organization key discovery.',
      inputSchema: {
        type: 'object',
        properties: {
          api_key: { type: 'string', description: 'HAI API key (optional, uses env if not set)' },
          preview: { type: 'boolean', description: 'Preview mode (default true)' },
        },
      },
    },
    {
      name: 'jacs_setup_instructions',
      description: 'Get DNS and well-known setup instructions for a domain.',
      inputSchema: {
        type: 'object',
        properties: {
          domain: { type: 'string', description: 'Domain name for setup' },
        },
        required: ['domain'],
      },
    },
    {
      name: 'jacs_trust_agent',
      description: 'Add an agent to the local trust store.',
      inputSchema: {
        type: 'object',
        properties: {
          agent_json: { type: 'string', description: 'Agent JSON document to trust' },
        },
        required: ['agent_json'],
      },
    },
    {
      name: 'jacs_list_trusted',
      description: 'List all agent IDs in the local trust store.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_is_trusted',
      description: 'Check if a specific agent is in the local trust store.',
      inputSchema: {
        type: 'object',
        properties: {
          agent_id: { type: 'string', description: 'Agent ID to check' },
        },
        required: ['agent_id'],
      },
    },
    {
      name: 'jacs_reencrypt_key',
      description: 'Re-encrypt the private key with a new password.',
      inputSchema: {
        type: 'object',
        properties: {
          old_password: { type: 'string', description: 'Current password' },
          new_password: { type: 'string', description: 'New password' },
        },
        required: ['old_password', 'new_password'],
      },
    },
  ];
}

/**
 * Handle a JACS MCP tool call. Returns a JSON string result.
 *
 * Use this with `server.setRequestHandler(CallToolRequestSchema, ...)`.
 */
export async function handleJacsMcpToolCall(
  client: JacsClient,
  toolName: string,
  args: Record<string, any>,
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

  try {
    switch (toolName) {
      case 'jacs_sign_document': {
        const data = JSON.parse(args.data);
        const signed = await client.signMessage(data);
        return text(JSON.stringify({
          success: true, documentId: signed.documentId,
          agentId: signed.agentId, timestamp: signed.timestamp,
          raw: signed.raw,
        }));
      }

      case 'jacs_verify_document': {
        const result = await client.verify(args.document);
        return text(JSON.stringify({
          success: result.valid, valid: result.valid,
          signerId: result.signerId, timestamp: result.timestamp,
          data: result.data, errors: result.errors,
        }));
      }

      case 'jacs_verify_by_id': {
        const result = await client.verifyById(args.document_id);
        return text(JSON.stringify({
          success: result.valid, valid: result.valid,
          errors: result.errors,
        }));
      }

      case 'jacs_create_agreement': {
        const doc = JSON.parse(args.document);
        const opts: any = {};
        if (args.question) opts.question = args.question;
        if (args.timeout) opts.timeout = args.timeout;
        if (args.quorum !== undefined) opts.quorum = args.quorum;
        const signed = await client.createAgreement(doc, args.agent_ids, opts);
        return text(JSON.stringify({
          success: true, documentId: signed.documentId,
          agentId: signed.agentId, raw: signed.raw,
        }));
      }

      case 'jacs_sign_agreement': {
        const signed = await client.signAgreement(args.document);
        return text(JSON.stringify({
          success: true, documentId: signed.documentId,
          agentId: signed.agentId, raw: signed.raw,
        }));
      }

      case 'jacs_check_agreement': {
        const status = await client.checkAgreement(args.document);
        return text(JSON.stringify({ success: true, ...status }));
      }

      case 'jacs_audit': {
        const result = await client.audit(
          args.recent_n !== undefined ? { recentN: args.recent_n } : undefined,
        );
        return text(JSON.stringify({ success: true, ...result }));
      }

      case 'jacs_sign_file': {
        const signed = await client.signFile(args.file_path, args.embed || false);
        return text(JSON.stringify({
          success: true, documentId: signed.documentId,
          agentId: signed.agentId, raw: signed.raw,
        }));
      }

      case 'jacs_verify_self': {
        const result = await client.verifySelf();
        return text(JSON.stringify({
          success: result.valid, valid: result.valid,
          signerId: result.signerId, errors: result.errors,
        }));
      }

      case 'jacs_agent_info': {
        const nativeAgent = extractNativeAgent(client);
        let diagnostics = {};
        try { diagnostics = JSON.parse(nativeAgent.diagnostics()); } catch { /* ok */ }
        return text(JSON.stringify({
          agentId: client.agentId, name: client.name,
          strict: client.strict, diagnostics,
        }));
      }

      case 'fetch_agent_key': {
        const keyInfo = fetchRemoteKey(args.agent_id, args.version || null);
        return text(JSON.stringify({
          success: true, agentId: keyInfo.agentId,
          version: keyInfo.version, algorithm: keyInfo.algorithm,
          publicKeyHash: keyInfo.publicKeyHash,
        }));
      }

      case 'jacs_register': {
        const nativeAgent = extractNativeAgent(client);
        const result = await nativeAgent.registerWithHai(
          args.api_key || null, null, args.preview !== false,
        );
        return text(result);
      }

      case 'jacs_setup_instructions': {
        const nativeAgent = extractNativeAgent(client);
        const result = await nativeAgent.getSetupInstructions(args.domain, null);
        return text(result);
      }

      case 'jacs_trust_agent': {
        const result = client.trustAgent(args.agent_json);
        return text(JSON.stringify({ success: true, result }));
      }

      case 'jacs_list_trusted': {
        const agents = client.listTrustedAgents();
        return text(JSON.stringify({ success: true, trustedAgents: agents }));
      }

      case 'jacs_is_trusted': {
        const trusted = client.isTrusted(args.agent_id);
        return text(JSON.stringify({ agentId: args.agent_id, trusted }));
      }

      case 'jacs_reencrypt_key': {
        const nativeAgent = extractNativeAgent(client);
        await nativeAgent.reencryptKey(args.old_password, args.new_password);
        return text(JSON.stringify({ success: true, message: 'Key re-encrypted' }));
      }

      default:
        return text(JSON.stringify({ error: `Unknown tool: ${toolName}` }));
    }
  } catch (err: any) {
    return text(JSON.stringify({ success: false, error: String(err) }));
  }
}

/**
 * Register all JACS tools on an MCP Server instance.
 *
 * Call this once during server setup to add JACS signing, verification,
 * agreements, trust, audit, and HAI integration tools.
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
 * const client = await JacsClient.quickstart();
 * registerJacsTools(server, client);
 * ```
 */
export function registerJacsTools(server: any, client: JacsClient): void {
  // Lazy import MCP SDK schemas — only needed if registering tools
  let ListToolsRequestSchema: any;
  let CallToolRequestSchema: any;
  try {
    const types = require('@modelcontextprotocol/sdk/types.js');
    ListToolsRequestSchema = types.ListToolsRequestSchema;
    CallToolRequestSchema = types.CallToolRequestSchema;
  } catch {
    throw new Error(
      '@modelcontextprotocol/sdk is required for registerJacsTools. ' +
      'Install it with: npm install @modelcontextprotocol/sdk'
    );
  }

  const tools = getJacsMcpToolDefinitions();

  server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
    const { name, arguments: args } = request.params;
    return handleJacsMcpToolCall(client, name, args || {});
  });
}
