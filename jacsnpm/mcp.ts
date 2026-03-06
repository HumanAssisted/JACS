// JACS MCP — Transport proxy + partial compatibility layer for Node.js MCP servers
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
import { JacsAgent } from './index.js';
import { JacsClient } from './client.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const isStdioTransport = (transport: any): boolean => {
  return transport.constructor.name === 'StdioServerTransport' ||
         transport.constructor.name === 'StdioClientTransport';
};

const DEFAULT_KEYS_BASE_URL = 'https://hai.ai';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

function parseBooleanEnv(value: string | undefined): boolean | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no') return false;
  return undefined;
}

function resolveLocalOnly(override?: boolean): boolean {
  const envValue = parseBooleanEnv(process.env.JACS_MCP_LOCAL_ONLY);
  if (override === false || envValue === false) {
    throw new Error(
      'JACS MCP local mode only: disabling local-only mode is not allowed.'
    );
  }
  return true;
}

function resolveAllowUnsignedFallback(override?: boolean): boolean {
  if (typeof override === 'boolean') return override;
  return parseBooleanEnv(process.env.JACS_MCP_ALLOW_UNSIGNED_FALLBACK) ?? false;
}

function isUntrustAllowed(): boolean {
  return parseBooleanEnv(process.env.JACS_MCP_ALLOW_UNTRUST) === true;
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.trim().replace(/^\[|\]$/g, '').toLowerCase();
  return LOOPBACK_HOSTS.has(normalized);
}

function isLocalHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    return isLoopbackHost(parsed.hostname);
  } catch {
    return false;
  }
}

function extractTransportUrl(transport: any): string | null {
  const candidates = ['url', 'endpoint', 'uri', 'serverUrl'];
  for (const key of candidates) {
    const value = transport?.[key];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function assertLocalTransport(transport: any): void {
  if (isStdioTransport(transport)) {
    return;
  }

  const transportUrl = extractTransportUrl(transport);
  if (transportUrl && isLocalHttpUrl(transportUrl)) {
    return;
  }

  throw new Error(
    'JACS MCP local mode only: transport must use stdio or a loopback URL ' +
    '(localhost/127.0.0.1/::1).'
  );
}

function debugLog(proxyId: string, enabled: boolean, ...args: any[]): void {
  if (enabled) console.error(`[${proxyId}]`, ...args);
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, '');
}

function resolveKeysBaseUrl(override?: unknown): string {
  if (typeof override === 'string' && override.trim()) {
    return normalizeBaseUrl(override);
  }
  if (process.env.JACS_KEYS_BASE_URL && process.env.JACS_KEYS_BASE_URL.trim()) {
    return normalizeBaseUrl(process.env.JACS_KEYS_BASE_URL);
  }
  if (process.env.HAI_KEYS_BASE_URL && process.env.HAI_KEYS_BASE_URL.trim()) {
    return normalizeBaseUrl(process.env.HAI_KEYS_BASE_URL);
  }
  return DEFAULT_KEYS_BASE_URL;
}

function normalizePublicKeyHash(publicKeyHash: string): string {
  const trimmed = publicKeyHash.trim();
  if (!trimmed) {
    throw new Error('public_key_hash cannot be empty');
  }
  return trimmed.startsWith('sha256:') ? trimmed : `sha256:${trimmed}`;
}

async function fetchJson(url: string): Promise<any> {
  if (typeof fetch !== 'function') {
    throw new Error('Global fetch() is unavailable in this runtime');
  }
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from key lookup endpoint: ${body || response.statusText}`);
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`Key lookup endpoint returned non-JSON response: ${url}`);
  }
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
      'JacsClient has no loaded agent. Call quickstart({ name, domain }), ephemeral(), load(), or create() before wrapping with JACSTransportProxy.'
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
 * Incoming messages are verified with `verifyResponse()`.
 *
 * Security defaults:
 * - local-only transport enforcement (`stdio` or loopback URL)
 * - fail-closed on signing/verification errors
 *
 * Local-only mode is mandatory and cannot be disabled.
 *
 * Optional fallback behavior:
 * - `allowUnsignedFallback: true` (or `JACS_MCP_ALLOW_UNSIGNED_FALLBACK=true`)
 */
export class JACSTransportProxy implements Transport {
  private nativeAgent: JacsAgent;
  private proxyId: string;
  private debug: boolean;
  private allowUnsignedFallback: boolean;

  // MCP SDK sets these
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  /**
   * Local/security policy options for MCP transport proxy behavior.
   */
  static readonly DEFAULT_LOCAL_ONLY = true;

  constructor(
    private transport: Transport,
    clientOrAgent: JacsClient | JacsAgent,
    role: "client" | "server" = "server",
    options: JACSTransportProxyOptions = {},
  ) {
    this.nativeAgent = extractNativeAgent(clientOrAgent);
    this.proxyId = `JACS_${role.toUpperCase()}_PROXY`;
    const localOnly = resolveLocalOnly(options.localOnly);
    this.allowUnsignedFallback = resolveAllowUnsignedFallback(options.allowUnsignedFallback);

    if (localOnly) {
      assertLocalTransport(transport);
    }

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
      if (this.allowUnsignedFallback) {
        console.error(`[${this.proxyId}] Signing failed, sending plain message:`, signError);
        await this.transport.send(message);
        return;
      }
      const error = signError instanceof Error ? signError : new Error(String(signError));
      throw new Error(
        `[${this.proxyId}] JACS signing failed and unsigned fallback is disabled: ${error.message}`
      );
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
        } catch (verifyError) {
          if (!this.allowUnsignedFallback) {
            const error = verifyError instanceof Error ? verifyError : new Error(String(verifyError));
            throw new Error(
              `JACS verification failed and unsigned fallback is disabled: ${error.message}`
            );
          }

          // Not a JACS artifact (or verification failure), parse as plain JSON
          debugLog(this.proxyId, this.debug, 'INCOMING: verification failed, parsing as plain JSON');
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

export interface JACSTransportProxyOptions {
  /**
   * Reserved for compatibility. Local-only mode is always enforced.
   * Passing false throws an error.
   */
  localOnly?: boolean;
  /**
   * Allow fallback to unsigned/plain MCP messages when JACS signing or
   * verification fails. Default: false (fail closed).
   */
  allowUnsignedFallback?: boolean;
}

/**
 * Create a transport proxy from a pre-loaded JacsClient or JacsAgent.
 */
export function createJACSTransportProxy(
  transport: Transport,
  clientOrAgent: JacsClient | JacsAgent,
  role: "client" | "server" = "server",
  options: JACSTransportProxyOptions = {},
): JACSTransportProxy {
  return new JACSTransportProxy(transport, clientOrAgent, role, options);
}

/**
 * Create a transport proxy by loading a JACS agent from a config file.
 * Awaits agent loading before returning, so the proxy is immediately usable.
 */
export async function createJACSTransportProxyAsync(
  transport: Transport,
  configPath: string,
  role: "client" | "server" = "server",
  options: JACSTransportProxyOptions = {},
): Promise<JACSTransportProxy> {
  const agent = new JacsAgent();
  await agent.load(configPath);
  return new JACSTransportProxy(transport, agent, role, options);
}

// ---------------------------------------------------------------------------
// MCP Tool Definitions — partial compatibility layer over the canonical Rust contract
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
 * Returns the Node.js MCP compatibility tool definitions.
 *
 * The canonical full MCP contract lives in the Rust `jacs-mcp` crate. This
 * helper exposes the subset and compatibility aliases supported by jacsnpm.
 */
export function getJacsMcpToolDefinitions(): JacsMcpToolDef[] {
  return [
    {
      name: 'jacs_sign_document',
      description: 'Sign arbitrary JSON content with JACS cryptographic provenance.',
      inputSchema: {
        type: 'object',
        properties: {
          content: { type: 'string', description: 'JSON string of content to sign' },
          content_type: { type: 'string', description: 'Optional MIME type (default application/json)' },
        },
        required: ['content'],
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
          context: { type: 'string', description: 'Additional context for signers' },
          timeout: { type: 'string', description: 'ISO 8601 deadline' },
          quorum: { type: 'number', description: 'Minimum signatures required (M-of-N)' },
          required_algorithms: {
            type: 'array',
            items: { type: 'string' },
            description: 'Only allow these signing algorithms',
          },
          minimum_strength: { type: 'string', description: 'Minimum crypto strength requirement' },
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
          signed_agreement: { type: 'string', description: 'The agreement document to sign' },
          agreement_fieldname: { type: 'string', description: 'Optional custom agreement field name' },
        },
        required: ['signed_agreement'],
      },
    },
    {
      name: 'jacs_check_agreement',
      description: 'Check the status of a multi-party agreement.',
      inputSchema: {
        type: 'object',
        properties: {
          signed_agreement: { type: 'string', description: 'The agreement document to check' },
          agreement_fieldname: { type: 'string', description: 'Optional custom agreement field name' },
        },
        required: ['signed_agreement'],
      },
    },
    {
      name: 'jacs_audit',
      description: 'Run a JACS security audit on documents and keys.',
      inputSchema: {
        type: 'object',
        properties: {
          config_path: { type: 'string', description: 'Optional path to jacs.config.json' },
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
      name: 'jacs_share_public_key',
      description: 'Share this agent public key PEM for trust bootstrap and signature verification.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_share_agent',
      description: 'Legacy compatibility alias for jacs_export_agent.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_export_agent',
      description: 'Export this agent self-signed JACS document for trust establishment.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_export_agent_card',
      description: "Export this agent's A2A Agent Card for discovery.",
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_wrap_a2a_artifact',
      description: 'Wrap an A2A artifact with JACS provenance signature.',
      inputSchema: {
        type: 'object',
        properties: {
          artifact_json: { type: 'string', description: 'JSON string of the A2A artifact payload' },
          artifact_type: { type: 'string', description: 'Artifact type label' },
          parent_signatures: {
            type: 'string',
            description: 'Optional JSON array of parent signatures for chain of custody',
          },
        },
        required: ['artifact_json', 'artifact_type'],
      },
    },
    {
      name: 'jacs_verify_a2a_artifact',
      description: 'Verify a JACS-wrapped A2A artifact.',
      inputSchema: {
        type: 'object',
        properties: {
          wrapped_artifact: { type: 'string', description: 'The wrapped artifact JSON string' },
        },
        required: ['wrapped_artifact'],
      },
    },
    {
      name: 'jacs_assess_a2a_agent',
      description: 'Assess a remote A2A agent card under the requested trust policy.',
      inputSchema: {
        type: 'object',
        properties: {
          agent_card_json: { type: 'string', description: 'Remote A2A Agent Card JSON' },
          policy: { type: 'string', description: "Trust policy: 'open', 'verified', or 'strict'" },
        },
        required: ['agent_card_json'],
      },
    },
    {
      name: 'fetch_agent_key',
      description: 'Fetch an agent public key from the registry when it is not available locally.',
      inputSchema: {
        type: 'object',
        properties: {
          jacs_id: { type: 'string', description: 'Agent JACS ID (UUID) for /agents/{id}/keys/{version} lookups' },
          version: { type: 'string', description: 'Key version (default: latest)' },
          public_key_hash: { type: 'string', description: 'Optional sha256:<hex> hash for /keys/by-hash lookups' },
          base_url: { type: 'string', description: 'Optional registry base URL (default: https://hai.ai)' },
        },
      },
    },
    {
      name: 'jacs_register',
      description: 'Register the local agent with a remote registry (reserved for compatibility).',
      inputSchema: {
        type: 'object',
        properties: {
          preview: { type: 'boolean', description: 'Validate registration payload without committing changes' },
          base_url: { type: 'string', description: 'Optional registry base URL' },
          api_key: { type: 'string', description: 'Optional API key (if required by registry)' },
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
      name: 'jacs_trust_agent_with_key',
      description: 'Add an agent to the trust store by verifying the agent document with an explicit public key PEM.',
      inputSchema: {
        type: 'object',
        properties: {
          agent_json: { type: 'string', description: 'Agent JSON document to trust' },
          public_key_pem: { type: 'string', description: 'PEM-encoded public key for self-signature verification' },
        },
        required: ['agent_json', 'public_key_pem'],
      },
    },
    {
      name: 'jacs_list_trusted',
      description: 'Legacy compatibility alias for jacs_list_trusted_agents.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_list_trusted_agents',
      description: 'List all agent IDs in the local trust store.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'jacs_get_trusted_agent',
      description: 'Get a trusted agent document by agent ID.',
      inputSchema: {
        type: 'object',
        properties: {
          agent_id: { type: 'string', description: 'Agent ID to load from the local trust store' },
        },
        required: ['agent_id'],
      },
    },
    {
      name: 'jacs_untrust_agent',
      description: 'Remove an agent from the local trust store. Requires JACS_MCP_ALLOW_UNTRUST=true.',
      inputSchema: {
        type: 'object',
        properties: {
          agent_id: { type: 'string', description: 'Agent ID to remove from the local trust store' },
        },
        required: ['agent_id'],
      },
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
        const rawContent = typeof args.content === 'string' ? args.content : args.data;
        const data = JSON.parse(rawContent);
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
        if (args.context) opts.context = args.context;
        if (args.timeout) opts.timeout = args.timeout;
        if (args.quorum !== undefined) opts.quorum = args.quorum;
        if (args.required_algorithms) opts.requiredAlgorithms = args.required_algorithms;
        if (args.minimum_strength) opts.minimumStrength = args.minimum_strength;
        const signed = await client.createAgreement(doc, args.agent_ids, opts);
        return text(JSON.stringify({
          success: true, documentId: signed.documentId,
          agentId: signed.agentId, raw: signed.raw,
        }));
      }

      case 'jacs_sign_agreement': {
        const signed = await client.signAgreement(
          args.signed_agreement ?? args.document,
          args.agreement_fieldname,
        );
        return text(JSON.stringify({
          success: true, documentId: signed.documentId,
          agentId: signed.agentId, raw: signed.raw,
        }));
      }

      case 'jacs_check_agreement': {
        const status = await client.checkAgreement(
          args.signed_agreement ?? args.document,
          args.agreement_fieldname,
        );
        return text(JSON.stringify({ success: true, ...status }));
      }

      case 'jacs_audit': {
        const result = await client.audit(
          args.config_path !== undefined || args.recent_n !== undefined
            ? {
                configPath: args.config_path,
                recentN: args.recent_n,
              }
            : undefined,
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
          strict: client.strict,
          diagnostics,
        }));
      }

      case 'jacs_share_public_key': {
        const publicKey = (client as any).sharePublicKey
          ? (client as any).sharePublicKey()
          : (client as any).getPublicKey();
        return text(JSON.stringify({ success: true, publicKeyPem: publicKey }));
      }

      case 'jacs_share_agent':
      case 'jacs_export_agent': {
        const agentJson = (client as any).shareAgent
          ? (client as any).shareAgent()
          : (client as any).exportAgent();
        return text(JSON.stringify({ success: true, agentJson }));
      }

      case 'jacs_export_agent_card': {
        const agentCard = (client as any).exportAgentCard();
        return text(JSON.stringify({ success: true, agentCard }));
      }

      case 'jacs_wrap_a2a_artifact': {
        const artifact = JSON.parse(args.artifact_json);
        const parentSignatures =
          typeof args.parent_signatures === 'string' && args.parent_signatures.trim()
            ? JSON.parse(args.parent_signatures)
            : null;
        const wrappedArtifact = await (client as any).signArtifact(
          artifact,
          args.artifact_type,
          parentSignatures,
        );
        return text(JSON.stringify({ success: true, wrappedArtifact }));
      }

      case 'jacs_verify_a2a_artifact': {
        const verification = await (client as any).verifyArtifact(args.wrapped_artifact);
        return text(JSON.stringify({ success: true, ...verification }));
      }

      case 'jacs_assess_a2a_agent': {
        const { JACSA2AIntegration } = require('./a2a');
        const a2a = new JACSA2AIntegration(client, args.policy);
        const assessment = a2a.assessRemoteAgent(args.agent_card_json);
        return text(JSON.stringify({
          success: true,
          allowed: assessment.allowed,
          trustLevel: assessment.trustLevel,
          jacsRegistered: assessment.jacsRegistered,
          inTrustStore: assessment.inTrustStore,
          reason: assessment.reason,
        }));
      }

      case 'fetch_agent_key': {
        const baseUrl = resolveKeysBaseUrl(args.base_url);
        const byHash = typeof args.public_key_hash === 'string' ? args.public_key_hash.trim() : '';
        let lookupUrl: string;

        if (byHash) {
          const normalizedHash = normalizePublicKeyHash(byHash);
          lookupUrl = `${baseUrl}/jacs/v1/keys/by-hash/${encodeURIComponent(normalizedHash)}`;
        } else {
          const jacsId = typeof args.jacs_id === 'string' ? args.jacs_id.trim() : '';
          if (!jacsId) {
            throw new Error('fetch_agent_key requires jacs_id or public_key_hash');
          }
          const version =
            typeof args.version === 'string' && args.version.trim()
              ? args.version.trim()
              : 'latest';
          lookupUrl = `${baseUrl}/jacs/v1/agents/${encodeURIComponent(jacsId)}/keys/${encodeURIComponent(version)}`;
        }

        const lookup = await fetchJson(lookupUrl);
        return text(JSON.stringify({
          success: true,
          ...lookup,
        }));
      }

      case 'jacs_register': {
        const dynamicRegister = (client as any).register;
        if (typeof dynamicRegister === 'function') {
          const result = await dynamicRegister.call(client, args);
          return text(typeof result === 'string' ? result : JSON.stringify({ success: true, result }));
        }
        return text(JSON.stringify({
          success: false,
          error: 'jacs_register is not implemented in jacsnpm. Use the JACS SDK for registration workflows.',
        }));
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

      case 'jacs_trust_agent_with_key': {
        const result = (client as any).trustAgentWithKey(
          args.agent_json,
          args.public_key_pem,
        );
        return text(JSON.stringify({ success: true, result }));
      }

      case 'jacs_list_trusted':
      case 'jacs_list_trusted_agents': {
        const agents = client.listTrustedAgents();
        return text(JSON.stringify({ success: true, trustedAgents: agents }));
      }

      case 'jacs_get_trusted_agent': {
        const agentJson = (client as any).getTrustedAgent(args.agent_id);
        return text(JSON.stringify({ success: true, agentId: args.agent_id, agentJson }));
      }

      case 'jacs_untrust_agent': {
        if (!isUntrustAllowed()) {
          return text(JSON.stringify({
            success: false,
            agentId: args.agent_id,
            error: 'UNTRUST_DISABLED',
            message:
              'Untrusting is disabled for security. To enable, set ' +
              'JACS_MCP_ALLOW_UNTRUST=true when starting the MCP server.',
          }));
        }
        (client as any).untrustAgent(args.agent_id);
        return text(JSON.stringify({ success: true, agentId: args.agent_id }));
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
 * agreements, trust, audit, and registry integration tools.
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
