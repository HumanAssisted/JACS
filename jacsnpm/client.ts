/**
 * JACS Instance-Based Client API
 *
 * Provides `JacsClient`, a class that wraps its own `JacsAgent` instance so
 * multiple clients can coexist in the same process without shared mutable
 * global state. This is the recommended API for new code.
 *
 * @example
 * ```typescript
 * import { JacsClient } from '@hai.ai/jacs/client';
 *
 * const client = JacsClient.quickstart({ algorithm: 'ring-Ed25519' });
 * const signed = client.signMessage({ action: 'approve' });
 * const result = client.verify(signed.raw);
 * console.log(`Valid: ${result.valid}`);
 * ```
 */

import {
  JacsAgent,
  hashString,
  verifyString,
  createConfig,
  createAgent as nativeCreateAgent,
  trustAgent as nativeTrustAgent,
  listTrustedAgents as nativeListTrustedAgents,
  untrustAgent as nativeUntrustAgent,
  isTrusted as nativeIsTrusted,
  getTrustedAgent as nativeGetTrustedAgent,
  audit as nativeAudit,
} from './index';
import * as fs from 'fs';
import * as path from 'path';

import type {
  AgentInfo,
  SignedDocument,
  VerificationResult,
  Attachment,
  AgreementStatus,
  AuditOptions,
  QuickstartOptions,
  QuickstartInfo,
  CreateAgentOptions,
  LoadOptions,
} from './simple';

export type {
  AgentInfo,
  SignedDocument,
  VerificationResult,
  Attachment,
  AgreementStatus,
  AuditOptions,
  QuickstartOptions,
  QuickstartInfo,
  CreateAgentOptions,
  LoadOptions,
};

export { hashString, verifyString, createConfig };

// =============================================================================
// Agreement Options
// =============================================================================

export interface AgreementOptions {
  /** Optional question or purpose of the agreement. */
  question?: string;
  /** Optional additional context for signers. */
  context?: string;
  /** Optional custom field name for the agreement (default: "jacsAgreement"). */
  fieldName?: string;
  /** ISO 8601 deadline after which the agreement expires. */
  timeout?: string;
  /** Minimum number of signatures required (M-of-N). */
  quorum?: number;
  /** Only accept signatures from these algorithms. */
  requiredAlgorithms?: string[];
  /** Minimum strength: "classical" or "post-quantum". */
  minimumStrength?: string;
}

// =============================================================================
// JacsClient Options
// =============================================================================

export interface JacsClientOptions {
  /** Path to jacs.config.json (default: "./jacs.config.json"). */
  configPath?: string;
  /** Signing algorithm: "pq2025" (default), "ring-Ed25519", or "RSA-PSS". */
  algorithm?: string;
  /** Enable strict mode: verification failures throw instead of returning { valid: false }. */
  strict?: boolean;
}

// =============================================================================
// Helpers
// =============================================================================

function resolveStrict(explicit?: boolean): boolean {
  if (explicit !== undefined) {
    return explicit;
  }
  const envStrict = process.env.JACS_STRICT_MODE;
  return envStrict === 'true' || envStrict === '1';
}

function resolveConfigRelativePath(configPath: string, candidate: string): string {
  if (path.isAbsolute(candidate)) {
    return candidate;
  }
  return path.resolve(path.dirname(configPath), candidate);
}

function normalizeDocumentInput(document: any): string {
  if (typeof document === 'string') {
    return document;
  }
  if (document && typeof document === 'object') {
    if (typeof document.raw === 'string') {
      return document.raw;
    }
    if (typeof document.raw_json === 'string') {
      return document.raw_json;
    }
  }
  return JSON.stringify(document);
}

// =============================================================================
// JacsClient
// =============================================================================

/**
 * Instance-based JACS client. Each instance owns its own `JacsAgent` and
 * maintains independent state, so multiple clients can coexist in the same
 * process without interference.
 */
export class JacsClient {
  private agent: JacsAgent | null = null;
  private info: AgentInfo | null = null;
  private _strict: boolean = false;

  constructor(options?: JacsClientOptions) {
    this._strict = resolveStrict(options?.strict);
  }

  // ---------------------------------------------------------------------------
  // Static factories
  // ---------------------------------------------------------------------------

  /**
   * Zero-config factory: loads or creates a persistent agent.
   *
   * If a config file already exists at `options.configPath` (default
   * `./jacs.config.json`) the agent is loaded from it. Otherwise a new
   * agent is created with auto-generated keys.
   */
  static quickstart(options?: QuickstartOptions): JacsClient {
    const client = new JacsClient({ strict: options?.strict });
    const configPath = (options as any)?.configPath || './jacs.config.json';

    if (fs.existsSync(configPath)) {
      client.load(configPath);
      return client;
    }

    // Create new persistent agent
    const crypto = require('crypto');
    let password = process.env.JACS_PRIVATE_KEY_PASSWORD || '';
    if (!password) {
      const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      const lower = 'abcdefghijklmnopqrstuvwxyz';
      const digits = '0123456789';
      const special = '!@#$%^&*()-_=+';
      const all = upper + lower + digits + special;
      password =
        upper[crypto.randomInt(upper.length)] +
        lower[crypto.randomInt(lower.length)] +
        digits[crypto.randomInt(digits.length)] +
        special[crypto.randomInt(special.length)];
      for (let i = 4; i < 32; i++) {
        password += all[crypto.randomInt(all.length)];
      }

      const keysDir = './jacs_keys';
      fs.mkdirSync(keysDir, { recursive: true });
      const pwPath = path.join(keysDir, '.jacs_password');
      fs.writeFileSync(pwPath, password, { mode: 0o600 });
      process.env.JACS_PRIVATE_KEY_PASSWORD = password;
    }

    const algo = options?.algorithm || 'pq2025';
    client.create({
      name: 'jacs-agent',
      password,
      algorithm: algo,
    });

    return client;
  }

  /**
   * Create an ephemeral in-memory client for testing.
   * No config files, no key files, no environment variables needed.
   */
  static ephemeral(algorithm?: string): JacsClient {
    const client = new JacsClient();
    const nativeAgent = new JacsAgent();
    const resultJson = nativeAgent.ephemeral(algorithm ?? null);
    const result = JSON.parse(resultJson);

    client.agent = nativeAgent;
    client.info = {
      agentId: result.agent_id || '',
      name: result.name || 'ephemeral',
      publicKeyPath: '',
      configPath: '',
    };

    return client;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Load an agent from a configuration file.
   */
  load(configPath?: string, options?: LoadOptions): AgentInfo {
    if (options?.strict !== undefined) {
      this._strict = options.strict;
    }

    const requestedPath = configPath || './jacs.config.json';
    const resolvedConfigPath = path.resolve(requestedPath);

    if (!fs.existsSync(resolvedConfigPath)) {
      throw new Error(
        `Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`,
      );
    }

    this.agent = new JacsAgent();
    this.agent.load(resolvedConfigPath);

    const config = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8'));
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const [agentId] = agentIdVersion.split(':');
    const keyDir = resolveConfigRelativePath(
      resolvedConfigPath,
      config.jacs_key_directory || './jacs_keys',
    );

    this.info = {
      agentId: agentId || '',
      name: config.name || '',
      publicKeyPath: path.join(keyDir, 'jacs.public.pem'),
      configPath: resolvedConfigPath,
    };

    return this.info;
  }

  /**
   * Create a new agent with cryptographic keys.
   */
  create(options: CreateAgentOptions): AgentInfo {
    const resolvedPassword =
      options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
    if (!resolvedPassword) {
      throw new Error(
        'Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.',
      );
    }

    const resultJson = nativeCreateAgent(
      options.name,
      resolvedPassword,
      options.algorithm ?? null,
      options.dataDirectory ?? null,
      options.keyDirectory ?? null,
      options.configPath ?? null,
      options.agentType ?? null,
      options.description ?? null,
      options.domain ?? null,
      options.defaultStorage ?? null,
    );

    const result = JSON.parse(resultJson);
    const configPath = result.config_path || options.configPath || './jacs.config.json';

    this.info = {
      agentId: result.agent_id || '',
      name: result.name || options.name,
      publicKeyPath:
        result.public_key_path ||
        `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
      configPath,
    };

    // Load the agent from the newly created config
    this.agent = new JacsAgent();
    this.agent.load(path.resolve(configPath));

    return this.info;
  }

  /**
   * Clear internal state. After calling reset() you must call load(), create(),
   * quickstart(), or ephemeral() again before using signing/verification.
   */
  reset(): void {
    this.agent = null;
    this.info = null;
    this._strict = false;
  }

  /**
   * Alias for reset(). Satisfies the disposable pattern.
   */
  dispose(): void {
    this.reset();
  }

  [Symbol.dispose](): void {
    this.reset();
  }

  // ---------------------------------------------------------------------------
  // Getters
  // ---------------------------------------------------------------------------

  /** The current agent's UUID. */
  get agentId(): string {
    return this.info?.agentId || '';
  }

  /** The current agent's human-readable name. */
  get name(): string {
    return this.info?.name || '';
  }

  /** Whether strict mode is enabled. */
  get strict(): boolean {
    return this._strict;
  }

  // ---------------------------------------------------------------------------
  // Signing & Verification
  // ---------------------------------------------------------------------------

  private requireAgent(): JacsAgent {
    if (!this.agent) {
      throw new Error(
        'No agent loaded. Call quickstart(), ephemeral(), load(), or create() first.',
      );
    }
    return this.agent;
  }

  /**
   * Sign arbitrary data as a JACS message.
   */
  signMessage(data: any): SignedDocument {
    const agent = this.requireAgent();
    const docContent = {
      jacsType: 'message',
      jacsLevel: 'raw',
      content: data,
    };

    const result = agent.createDocument(
      JSON.stringify(docContent),
      null,
      null,
      true,
      null,
      null,
    );

    const doc = JSON.parse(result);
    return {
      raw: result,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  }

  /**
   * Verify a signed document and extract its content.
   */
  verify(signedDocument: string): VerificationResult {
    const agent = this.requireAgent();

    const trimmed = signedDocument.trim();
    if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      return {
        valid: false,
        signerId: '',
        timestamp: '',
        attachments: [],
        errors: [
          `Input does not appear to be a JSON document. If you have a document ID (e.g., 'uuid:version'), use verifyById() instead. Received: '${trimmed.substring(0, 50)}${trimmed.length > 50 ? '...' : ''}'`,
        ],
      };
    }

    let doc: any;
    try {
      doc = JSON.parse(signedDocument);
    } catch (e) {
      return {
        valid: false,
        signerId: '',
        timestamp: '',
        attachments: [],
        errors: [`Invalid JSON: ${e}`],
      };
    }

    try {
      agent.verifyDocument(signedDocument);

      const attachments: Attachment[] = (doc.jacsFiles || []).map((f: any) => ({
        filename: f.path || '',
        mimeType: f.mimetype || 'application/octet-stream',
        hash: f.sha256 || '',
        embedded: f.embed || false,
        content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
      }));

      return {
        valid: true,
        data: doc.content,
        signerId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
        attachments,
        errors: [],
      };
    } catch (e) {
      if (this._strict) {
        throw new Error(`Verification failed (strict mode): ${e}`);
      }
      return {
        valid: false,
        signerId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
        attachments: [],
        errors: [String(e)],
      };
    }
  }

  /**
   * Verify the loaded agent's integrity.
   */
  verifySelf(): VerificationResult {
    const agent = this.requireAgent();
    try {
      agent.verifyAgent();
      return {
        valid: true,
        signerId: this.info?.agentId || '',
        timestamp: '',
        attachments: [],
        errors: [],
      };
    } catch (e) {
      if (this._strict) {
        throw new Error(`Self-verification failed (strict mode): ${e}`);
      }
      return {
        valid: false,
        signerId: '',
        timestamp: '',
        attachments: [],
        errors: [String(e)],
      };
    }
  }

  /**
   * Verify a document by its storage ID ("uuid:version").
   */
  verifyById(documentId: string): VerificationResult {
    const agent = this.requireAgent();

    if (!documentId.includes(':')) {
      return {
        valid: false,
        signerId: '',
        timestamp: '',
        attachments: [],
        errors: [
          `Document ID must be in 'uuid:version' format, got '${documentId}'. Use verify() with the full JSON string instead.`,
        ],
      };
    }

    try {
      agent.verifyDocumentById(documentId);
      return {
        valid: true,
        signerId: '',
        timestamp: '',
        attachments: [],
        errors: [],
      };
    } catch (e) {
      if (this._strict) {
        throw new Error(`Verification failed (strict mode): ${e}`);
      }
      return {
        valid: false,
        signerId: '',
        timestamp: '',
        attachments: [],
        errors: [String(e)],
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Files
  // ---------------------------------------------------------------------------

  /**
   * Sign a file with optional content embedding.
   */
  signFile(filePath: string, embed: boolean = false): SignedDocument {
    const agent = this.requireAgent();

    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const docContent = {
      jacsType: 'file',
      jacsLevel: 'raw',
      filename: path.basename(filePath),
    };

    const result = agent.createDocument(
      JSON.stringify(docContent),
      null,
      null,
      true,
      filePath,
      embed,
    );

    const doc = JSON.parse(result);
    return {
      raw: result,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  }

  // ---------------------------------------------------------------------------
  // Agreements
  // ---------------------------------------------------------------------------

  /**
   * Create a multi-party agreement.
   *
   * Supports extended options: timeout, quorum, requiredAlgorithms, minimumStrength.
   */
  createAgreement(
    document: any,
    agentIds: string[],
    options?: AgreementOptions,
  ): SignedDocument {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);

    const hasExtendedOptions =
      options?.timeout ||
      options?.quorum !== undefined ||
      options?.requiredAlgorithms ||
      options?.minimumStrength;

    let result: string;
    if (hasExtendedOptions) {
      result = agent.createAgreementWithOptions(
        docString,
        agentIds,
        options?.question || null,
        options?.context || null,
        options?.fieldName || null,
        options?.timeout || null,
        options?.quorum ?? null,
        options?.requiredAlgorithms || null,
        options?.minimumStrength || null,
      );
    } else {
      result = agent.createAgreement(
        docString,
        agentIds,
        options?.question || null,
        options?.context || null,
        options?.fieldName || null,
      );
    }

    const doc = JSON.parse(result);
    return {
      raw: result,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  }

  /**
   * Sign an existing multi-party agreement.
   */
  signAgreement(document: any, fieldName?: string): SignedDocument {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);

    const result = agent.signAgreement(docString, fieldName || null);
    const doc = JSON.parse(result);

    return {
      raw: result,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  }

  /**
   * Check the status of a multi-party agreement.
   */
  checkAgreement(document: any, fieldName?: string): AgreementStatus {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);

    const result = agent.checkAgreement(docString, fieldName || null);
    return JSON.parse(result);
  }

  // ---------------------------------------------------------------------------
  // Agent management
  // ---------------------------------------------------------------------------

  /**
   * Update the agent document with new data and re-sign it.
   */
  updateAgent(newAgentData: any): string {
    const agent = this.requireAgent();
    const dataString =
      typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return agent.updateAgent(dataString);
  }

  /**
   * Update an existing document with new data and re-sign it.
   */
  updateDocument(
    documentId: string,
    newDocumentData: any,
    attachments?: string[],
    embed?: boolean,
  ): SignedDocument {
    const agent = this.requireAgent();
    const dataString =
      typeof newDocumentData === 'string'
        ? newDocumentData
        : JSON.stringify(newDocumentData);

    const result = agent.updateDocument(
      documentId,
      dataString,
      attachments || null,
      embed ?? null,
    );

    const doc = JSON.parse(result);
    return {
      raw: result,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  }

  // ---------------------------------------------------------------------------
  // Trust Store
  // ---------------------------------------------------------------------------

  trustAgent(agentJson: string): string {
    return nativeTrustAgent(agentJson);
  }

  listTrustedAgents(): string[] {
    return nativeListTrustedAgents();
  }

  untrustAgent(agentId: string): void {
    nativeUntrustAgent(agentId);
  }

  isTrusted(agentId: string): boolean {
    return nativeIsTrusted(agentId);
  }

  getTrustedAgent(agentId: string): string {
    return nativeGetTrustedAgent(agentId);
  }

  // ---------------------------------------------------------------------------
  // Audit
  // ---------------------------------------------------------------------------

  audit(options?: AuditOptions): Record<string, unknown> {
    const json = nativeAudit(
      options?.configPath ?? undefined,
      options?.recentN ?? undefined,
    );
    return JSON.parse(json) as Record<string, unknown>;
  }
}
