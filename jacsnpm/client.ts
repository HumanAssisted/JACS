/**
 * JACS Instance-Based Client API
 *
 * v0.7.0: Async-first API. All methods that call native JACS operations
 * return Promises by default. Use `*Sync` variants for synchronous execution.
 *
 * @example
 * ```typescript
 * import { JacsClient } from '@hai.ai/jacs/client';
 *
 * const client = await JacsClient.quickstart({
 *   name: 'my-agent',
 *   domain: 'agent.example.com',
 *   algorithm: 'pq2025',
 * });
 * const signed = await client.signMessage({ action: 'approve' });
 * const result = await client.verify(signed.raw);
 * console.log(`Valid: ${result.valid}`);
 * ```
 */

import {
  JacsAgent,
  hashString,
  createConfig,
  createAgentSync as nativeCreateAgentSync,
  createAgent as nativeCreateAgent,
  trustAgent as nativeTrustAgent,
  trustAgentWithKey as nativeTrustAgentWithKey,
  listTrustedAgents as nativeListTrustedAgents,
  untrustAgent as nativeUntrustAgent,
  isTrusted as nativeIsTrusted,
  getTrustedAgent as nativeGetTrustedAgent,
  auditSync as nativeAuditSync,
  audit as nativeAudit,
} from './index';
import * as fs from 'fs';
import * as path from 'path';
import { warnDeprecated } from './deprecation';

import type {
  AgentInfo,
  SignedDocument,
  VerificationResult,
  Attachment,
  AgreementStatus,
  AttestationVerificationResult,
  DsseEnvelope,
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
  AttestationVerificationResult,
  DsseEnvelope,
  AuditOptions,
  QuickstartOptions,
  QuickstartInfo,
  CreateAgentOptions,
  LoadOptions,
};

export { hashString, createConfig };

// =============================================================================
// Agreement Options
// =============================================================================

export interface AgreementOptions {
  question?: string;
  context?: string;
  fieldName?: string;
  timeout?: string;
  quorum?: number;
  requiredAlgorithms?: string[];
  minimumStrength?: string;
}

// =============================================================================
// JacsClient Options
// =============================================================================

export interface JacsClientOptions {
  configPath?: string;
  algorithm?: string;
  strict?: boolean;
}

export interface ClientArtifactVerificationResult {
  valid: boolean;
  /**
   * Extracted payload returned by native verifyResponse() when available.
   */
  verifiedPayload?: Record<string, unknown>;
  /**
   * Backward-compatibility field for one release: raw native verifyResponse() output.
   */
  verificationResult?: boolean | Record<string, unknown>;
  signerId: string;
  signerVersion: string;
  artifactType: string;
  timestamp: string;
  originalArtifact: Record<string, unknown>;
  error?: string;
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

function resolveCreatePaths(
  configPath?: string | null,
  dataDirectory?: string | null,
  keyDirectory?: string | null,
): { configPath: string; dataDirectory: string; keyDirectory: string } {
  const resolvedConfigPath = configPath ?? './jacs.config.json';
  const configDir = path.dirname(path.resolve(resolvedConfigPath));
  const cwd = path.resolve(process.cwd());

  return {
    configPath: resolvedConfigPath,
    dataDirectory: dataDirectory ?? (configDir === cwd ? './jacs_data' : path.join(configDir, 'jacs_data')),
    keyDirectory: keyDirectory ?? (configDir === cwd ? './jacs_keys' : path.join(configDir, 'jacs_keys')),
  };
}

function readSavedPassword(configPath: string): string {
  try {
    const resolvedConfigPath = path.resolve(configPath);
    const config = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8'));
    const keyDir = resolveConfigRelativePath(
      resolvedConfigPath,
      config.jacs_key_directory || './jacs_keys',
    );
    const passwordPath = path.join(keyDir, '.jacs_password');
    if (!fs.existsSync(passwordPath)) {
      return '';
    }
    return fs.readFileSync(passwordPath, 'utf8').trim();
  } catch {
    return '';
  }
}

function resolvePrivateKeyPassword(
  configPath?: string | null,
  explicitPassword?: string | null,
): string {
  if (explicitPassword && explicitPassword.length > 0) {
    return explicitPassword;
  }
  if (process.env.JACS_PRIVATE_KEY_PASSWORD) {
    return process.env.JACS_PRIVATE_KEY_PASSWORD;
  }
  if (configPath) {
    return readSavedPassword(configPath);
  }
  return '';
}

async function withTemporaryPasswordEnv<T>(password: string, fn: () => Promise<T>): Promise<T> {
  const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
  process.env.JACS_PRIVATE_KEY_PASSWORD = password;
  try {
    return await fn();
  } finally {
    if (previousPassword === undefined) {
      delete process.env.JACS_PRIVATE_KEY_PASSWORD;
    } else {
      process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
    }
  }
}

function withTemporaryPasswordEnvSync<T>(password: string, fn: () => T): T {
  const previousPassword = process.env.JACS_PRIVATE_KEY_PASSWORD;
  process.env.JACS_PRIVATE_KEY_PASSWORD = password;
  try {
    return fn();
  } finally {
    if (previousPassword === undefined) {
      delete process.env.JACS_PRIVATE_KEY_PASSWORD;
    } else {
      process.env.JACS_PRIVATE_KEY_PASSWORD = previousPassword;
    }
  }
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

function normalizeA2AVerificationResult(
  rawVerificationResult: unknown,
): {
  valid: boolean;
  verifiedPayload?: Record<string, unknown>;
  verificationResult: boolean | Record<string, unknown>;
} {
  if (typeof rawVerificationResult === 'boolean') {
    return {
      valid: rawVerificationResult,
      verificationResult: rawVerificationResult,
    };
  }

  if (rawVerificationResult && typeof rawVerificationResult === 'object') {
    const rawObj = rawVerificationResult as Record<string, unknown>;
    const payload = rawObj.payload;
    return {
      valid: true,
      verifiedPayload: payload && typeof payload === 'object'
        ? payload as Record<string, unknown>
        : undefined,
      verificationResult: rawObj,
    };
  }

  return {
    valid: false,
    verificationResult: false,
  };
}

function extractAgentInfo(resolvedConfigPath: string): AgentInfo {
  const config = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8'));
  const agentIdVersion = config.jacs_agent_id_and_version || '';
  const [agentId, version] = agentIdVersion.split(':');
  const dataDir = resolveConfigRelativePath(
    resolvedConfigPath,
    config.jacs_data_directory || './jacs_data',
  );
  const keyDir = resolveConfigRelativePath(
    resolvedConfigPath,
    config.jacs_key_directory || './jacs_keys',
  );
  const publicKeyFilename = config.jacs_agent_public_key_filename || 'jacs.public.pem';
  const privateKeyFilename = config.jacs_agent_private_key_filename || 'jacs.private.pem.enc';
  return {
    agentId: agentId || '',
    name: config.name || '',
    publicKeyPath: path.join(keyDir, publicKeyFilename),
    configPath: resolvedConfigPath,
    version: version || '',
    algorithm: config.jacs_agent_key_algorithm || 'pq2025',
    privateKeyPath: path.join(keyDir, privateKeyFilename),
    dataDirectory: dataDir,
    keyDirectory: keyDir,
    domain: config.domain || '',
    dnsRecord: config.dns_record || '',
  };
}

function requireQuickstartIdentity(options: QuickstartOptions | undefined): {
  name: string;
  domain: string;
  description: string;
} {
  if (!options || typeof options !== 'object') {
    throw new Error('JacsClient.quickstart() requires options.name and options.domain.');
  }

  const name = typeof options.name === 'string' ? options.name.trim() : '';
  const domain = typeof options.domain === 'string' ? options.domain.trim() : '';
  if (!name) {
    throw new Error('JacsClient.quickstart() requires options.name.');
  }
  if (!domain) {
    throw new Error('JacsClient.quickstart() requires options.domain.');
  }
  return {
    name,
    domain,
    description: options.description?.trim() || '',
  };
}

function parseSignedResult(result: string): SignedDocument {
  const doc = JSON.parse(result);
  return {
    raw: result,
    documentId: doc.jacsId || '',
    agentId: doc.jacsSignature?.agentID || '',
    timestamp: doc.jacsSignature?.date || '',
  };
}

function extractAttachmentsFromDocument(doc: any): Attachment[] {
  return (doc.jacsFiles || []).map((f: any) => ({
    filename: f.path || f.filename || '',
    mimeType: f.mimetype || f.mimeType || 'application/octet-stream',
    hash: f.sha256 || '',
    embedded: f.embed || false,
    content: (f.contents || f.content) ? Buffer.from(f.contents || f.content, 'base64') : undefined,
  }));
}

function ensurePassword(keyDirectory?: string): string {
  let password = process.env.JACS_PRIVATE_KEY_PASSWORD || '';
  if (!password) {
    const crypto = require('crypto');
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
    const persistPassword =
      process.env.JACS_SAVE_PASSWORD_FILE === '1' ||
      process.env.JACS_SAVE_PASSWORD_FILE === 'true';
    if (persistPassword) {
      const keysDir = keyDirectory || './jacs_keys';
      fs.mkdirSync(keysDir, { recursive: true });
      const pwPath = path.join(keysDir, '.jacs_password');
      fs.writeFileSync(pwPath, password, { mode: 0o600 });
    }
  }
  return password;
}

// =============================================================================
// JacsClient
// =============================================================================

export class JacsClient {
  private agent: JacsAgent | null = null;
  private info: AgentInfo | null = null;
  private privateKeyPassword: string | null = null;
  private _strict: boolean = false;

  constructor(options?: JacsClientOptions) {
    this._strict = resolveStrict(options?.strict);
  }

  // ---------------------------------------------------------------------------
  // Static factories (async)
  // ---------------------------------------------------------------------------

  /**
   * Factory: loads or creates a persistent agent.
   */
  static async quickstart(options: QuickstartOptions): Promise<JacsClient> {
    const { name, domain, description } = requireQuickstartIdentity(options);
    const client = new JacsClient({ strict: options?.strict });
    const paths = resolveCreatePaths(options?.configPath);
    const configPath = paths.configPath;

    if (fs.existsSync(configPath)) {
      await client.load(configPath);
      return client;
    }

    const password = ensurePassword(paths.keyDirectory);
    const algo = options?.algorithm || 'pq2025';
    await client.create({
      name,
      password,
      algorithm: algo,
      configPath,
      dataDirectory: paths.dataDirectory,
      keyDirectory: paths.keyDirectory,
      domain,
      description,
    });
    return client;
  }

  /**
   * Factory (sync variant).
   */
  static quickstartSync(options: QuickstartOptions): JacsClient {
    const { name, domain, description } = requireQuickstartIdentity(options);
    const client = new JacsClient({ strict: options?.strict });
    const paths = resolveCreatePaths(options?.configPath);
    const configPath = paths.configPath;

    if (fs.existsSync(configPath)) {
      client.loadSync(configPath);
      return client;
    }

    const password = ensurePassword(paths.keyDirectory);
    const algo = options?.algorithm || 'pq2025';
    client.createSync({
      name,
      password,
      algorithm: algo,
      configPath,
      dataDirectory: paths.dataDirectory,
      keyDirectory: paths.keyDirectory,
      domain,
      description,
    });
    return client;
  }

  /**
   * Create an ephemeral in-memory client for testing.
   */
  static async ephemeral(algorithm?: string): Promise<JacsClient> {
    const client = new JacsClient();
    const nativeAgent = new JacsAgent();
    const resultJson = await nativeAgent.ephemeral(algorithm ?? null);
    const result = JSON.parse(resultJson);
    client.agent = nativeAgent;
    client.info = {
      agentId: result.agent_id || '',
      name: result.name || 'ephemeral',
      publicKeyPath: '',
      configPath: '',
      version: result.version || '',
      algorithm: result.algorithm || 'pq2025',
      privateKeyPath: '',
      dataDirectory: '',
      keyDirectory: '',
      domain: '',
      dnsRecord: '',
    };
    return client;
  }

  /**
   * Create an ephemeral in-memory client (sync variant).
   */
  static ephemeralSync(algorithm?: string): JacsClient {
    const client = new JacsClient();
    const nativeAgent = new JacsAgent();
    const resultJson = nativeAgent.ephemeralSync(algorithm ?? null);
    const result = JSON.parse(resultJson);
    client.agent = nativeAgent;
    client.info = {
      agentId: result.agent_id || '',
      name: result.name || 'ephemeral',
      publicKeyPath: '',
      configPath: '',
      version: result.version || '',
      algorithm: result.algorithm || 'pq2025',
      privateKeyPath: '',
      dataDirectory: '',
      keyDirectory: '',
      domain: '',
      dnsRecord: '',
    };
    return client;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  async load(configPath?: string, options?: LoadOptions): Promise<AgentInfo> {
    if (options?.strict !== undefined) {
      this._strict = options.strict;
    }
    const requestedPath = configPath || './jacs.config.json';
    const resolvedConfigPath = path.resolve(requestedPath);
    if (!fs.existsSync(resolvedConfigPath)) {
      throw new Error(`Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`);
    }
    const resolvedPassword = resolvePrivateKeyPassword(resolvedConfigPath);
    this.agent = new JacsAgent();
    this.privateKeyPassword = resolvedPassword || null;
    if (resolvedPassword) {
      await withTemporaryPasswordEnv(resolvedPassword, async () => {
        await this.agent!.load(resolvedConfigPath);
      });
    } else {
      await this.agent.load(resolvedConfigPath);
    }
    this.info = extractAgentInfo(resolvedConfigPath);
    return this.info;
  }

  loadSync(configPath?: string, options?: LoadOptions): AgentInfo {
    if (options?.strict !== undefined) {
      this._strict = options.strict;
    }
    const requestedPath = configPath || './jacs.config.json';
    const resolvedConfigPath = path.resolve(requestedPath);
    if (!fs.existsSync(resolvedConfigPath)) {
      throw new Error(`Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`);
    }
    const resolvedPassword = resolvePrivateKeyPassword(resolvedConfigPath);
    this.agent = new JacsAgent();
    this.privateKeyPassword = resolvedPassword || null;
    if (resolvedPassword) {
      withTemporaryPasswordEnvSync(resolvedPassword, () => {
        this.agent!.loadSync(resolvedConfigPath);
      });
    } else {
      this.agent.loadSync(resolvedConfigPath);
    }
    this.info = extractAgentInfo(resolvedConfigPath);
    return this.info;
  }

  async create(options: CreateAgentOptions): Promise<AgentInfo> {
    const resolvedPassword = resolvePrivateKeyPassword(options.configPath ?? null, options.password ?? null);
    if (!resolvedPassword) {
      throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
    }
    const normalizedOptions = {
      ...options,
      ...resolveCreatePaths(options.configPath ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null),
    };
    const resultJson = await nativeCreateAgent(
      normalizedOptions.name, resolvedPassword, normalizedOptions.algorithm ?? null, normalizedOptions.dataDirectory ?? null,
      normalizedOptions.keyDirectory ?? null, normalizedOptions.configPath ?? null, normalizedOptions.agentType ?? null,
      normalizedOptions.description ?? null, normalizedOptions.domain ?? null, normalizedOptions.defaultStorage ?? null,
    );
    const result = JSON.parse(resultJson);
    const cfgPath = result.config_path || normalizedOptions.configPath || './jacs.config.json';
    const dataDirectory = result.data_directory || normalizedOptions.dataDirectory || './jacs_data';
    const keyDirectory = result.key_directory || normalizedOptions.keyDirectory || './jacs_keys';
    const publicKeyPath = result.public_key_path || `${keyDirectory}/jacs.public.pem`;
    const privateKeyPath = result.private_key_path || `${keyDirectory}/jacs.private.pem.enc`;
    this.info = {
      agentId: result.agent_id || '',
      name: result.name || normalizedOptions.name,
      publicKeyPath,
      configPath: cfgPath,
      version: result.version || '',
      algorithm: result.algorithm || normalizedOptions.algorithm || 'pq2025',
      privateKeyPath,
      dataDirectory,
      keyDirectory,
      domain: result.domain || normalizedOptions.domain || '',
      dnsRecord: result.dns_record || '',
    };
    this.agent = new JacsAgent();
    this.privateKeyPassword = resolvedPassword;
    await withTemporaryPasswordEnv(resolvedPassword, async () => {
      await this.agent!.load(path.resolve(cfgPath));
    });
    return this.info;
  }

  createSync(options: CreateAgentOptions): AgentInfo {
    const resolvedPassword = resolvePrivateKeyPassword(options.configPath ?? null, options.password ?? null);
    if (!resolvedPassword) {
      throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
    }
    const normalizedOptions = {
      ...options,
      ...resolveCreatePaths(options.configPath ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null),
    };
    const resultJson = nativeCreateAgentSync(
      normalizedOptions.name, resolvedPassword, normalizedOptions.algorithm ?? null, normalizedOptions.dataDirectory ?? null,
      normalizedOptions.keyDirectory ?? null, normalizedOptions.configPath ?? null, normalizedOptions.agentType ?? null,
      normalizedOptions.description ?? null, normalizedOptions.domain ?? null, normalizedOptions.defaultStorage ?? null,
    );
    const result = JSON.parse(resultJson);
    const cfgPath = result.config_path || normalizedOptions.configPath || './jacs.config.json';
    const dataDirectory = result.data_directory || normalizedOptions.dataDirectory || './jacs_data';
    const keyDirectory = result.key_directory || normalizedOptions.keyDirectory || './jacs_keys';
    const publicKeyPath = result.public_key_path || `${keyDirectory}/jacs.public.pem`;
    const privateKeyPath = result.private_key_path || `${keyDirectory}/jacs.private.pem.enc`;
    this.info = {
      agentId: result.agent_id || '',
      name: result.name || normalizedOptions.name,
      publicKeyPath,
      configPath: cfgPath,
      version: result.version || '',
      algorithm: result.algorithm || normalizedOptions.algorithm || 'pq2025',
      privateKeyPath,
      dataDirectory,
      keyDirectory,
      domain: result.domain || normalizedOptions.domain || '',
      dnsRecord: result.dns_record || '',
    };
    this.agent = new JacsAgent();
    this.privateKeyPassword = resolvedPassword;
    withTemporaryPasswordEnvSync(resolvedPassword, () => {
      this.agent!.loadSync(path.resolve(cfgPath));
    });
    return this.info;
  }

  reset(): void {
    this.agent = null;
    this.info = null;
    this.privateKeyPassword = null;
    this._strict = false;
  }

  dispose(): void {
    this.reset();
  }

  [Symbol.dispose](): void {
    this.reset();
  }

  // ---------------------------------------------------------------------------
  // Getters
  // ---------------------------------------------------------------------------

  get agentId(): string {
    return this.info?.agentId || '';
  }

  get name(): string {
    return this.info?.name || '';
  }

  get strict(): boolean {
    return this._strict;
  }

  private readStoredDocumentById(documentId: string): any | null {
    if (!this.info) {
      return null;
    }
    try {
      const configPath = path.resolve(this.info.configPath);
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      const dataDir = resolveConfigRelativePath(
        configPath,
        config.jacs_data_directory || './jacs_data',
      );
      const docPath = path.join(dataDir, 'documents', `${documentId}.json`);
      if (!fs.existsSync(docPath)) {
        return null;
      }
      return JSON.parse(fs.readFileSync(docPath, 'utf8'));
    } catch {
      return null;
    }
  }

  /**
   * Internal access to the native JacsAgent for A2A and other low-level integrations.
   * @internal
   */
  get _agent(): JacsAgent {
    return this.requireAgent();
  }

  // ---------------------------------------------------------------------------
  // Signing & Verification
  // ---------------------------------------------------------------------------

  private requireAgent(): JacsAgent {
    if (!this.agent) {
      throw new Error('No agent loaded. Call quickstart({ name, domain }), ephemeral(), load(), or create() first.');
    }
    return this.agent;
  }

  private async withPrivateKeyPassword<T>(operation: (agent: JacsAgent) => Promise<T>): Promise<T> {
    const agent = this.requireAgent();
    if (!this.privateKeyPassword) {
      return operation(agent);
    }
    return withTemporaryPasswordEnv(this.privateKeyPassword, () => operation(agent));
  }

  private withPrivateKeyPasswordSync<T>(operation: (agent: JacsAgent) => T): T {
    const agent = this.requireAgent();
    if (!this.privateKeyPassword) {
      return operation(agent);
    }
    return withTemporaryPasswordEnvSync(this.privateKeyPassword, () => operation(agent));
  }

  async signMessage(data: any): Promise<SignedDocument> {
    const docContent = { jacsType: 'message', jacsLevel: 'raw', content: data };
    return this.withPrivateKeyPassword(async (agent) => {
      const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, null, null);
      return parseSignedResult(result);
    });
  }

  signMessageSync(data: any): SignedDocument {
    const docContent = { jacsType: 'message', jacsLevel: 'raw', content: data };
    return this.withPrivateKeyPasswordSync((agent) => {
      const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, null, null);
      return parseSignedResult(result);
    });
  }

  async verify(signedDocument: string): Promise<VerificationResult> {
    const agent = this.requireAgent();
    const trimmed = signedDocument.trim();
    if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Input does not appear to be a JSON document. If you have a document ID (e.g., 'uuid:version'), use verifyById() instead. Received: '${trimmed.substring(0, 50)}${trimmed.length > 50 ? '...' : ''}'`] };
    }
    let doc: any;
    try { doc = JSON.parse(signedDocument); } catch (e) {
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Invalid JSON: ${e}`] };
    }
    try {
      await agent.verifyDocument(signedDocument);
      const attachments: Attachment[] = extractAttachmentsFromDocument(doc);
      return { valid: true, data: doc.content, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments, errors: [] };
    } catch (e) {
      if (this._strict) throw new Error(`Verification failed (strict mode): ${e}`);
      return { valid: false, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments: [], errors: [String(e)] };
    }
  }

  verifySync(signedDocument: string): VerificationResult {
    const agent = this.requireAgent();
    const trimmed = signedDocument.trim();
    if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Input does not appear to be a JSON document.`] };
    }
    let doc: any;
    try { doc = JSON.parse(signedDocument); } catch (e) {
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Invalid JSON: ${e}`] };
    }
    try {
      agent.verifyDocumentSync(signedDocument);
      const attachments: Attachment[] = extractAttachmentsFromDocument(doc);
      return { valid: true, data: doc.content, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments, errors: [] };
    } catch (e) {
      if (this._strict) throw new Error(`Verification failed (strict mode): ${e}`);
      return { valid: false, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments: [], errors: [String(e)] };
    }
  }

  async verifySelf(): Promise<VerificationResult> {
    const agent = this.requireAgent();
    try {
      await agent.verifyAgent();
      return { valid: true, signerId: this.info?.agentId || '', timestamp: '', attachments: [], errors: [] };
    } catch (e) {
      if (this._strict) throw new Error(`Self-verification failed (strict mode): ${e}`);
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
    }
  }

  verifySelfSync(): VerificationResult {
    const agent = this.requireAgent();
    try {
      agent.verifyAgentSync();
      return { valid: true, signerId: this.info?.agentId || '', timestamp: '', attachments: [], errors: [] };
    } catch (e) {
      if (this._strict) throw new Error(`Self-verification failed (strict mode): ${e}`);
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
    }
  }

  async verifyById(documentId: string): Promise<VerificationResult> {
    const agent = this.requireAgent();
    if (!documentId.includes(':')) {
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Document ID must be in 'uuid:version' format, got '${documentId}'.`] };
    }
    try {
      await agent.verifyDocumentById(documentId);
      const storedJson = await agent.getDocumentById(documentId);
      const stored = JSON.parse(storedJson);
      return {
        valid: true,
        signerId: stored?.jacsSignature?.agentID || '',
        timestamp: stored?.jacsSignature?.date || '',
        attachments: extractAttachmentsFromDocument(stored || {}),
        errors: [],
      };
    } catch (e) {
      if (this._strict) throw new Error(`Verification failed (strict mode): ${e}`);
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
    }
  }

  verifyByIdSync(documentId: string): VerificationResult {
    const agent = this.requireAgent();
    if (!documentId.includes(':')) {
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Document ID must be in 'uuid:version' format, got '${documentId}'.`] };
    }
    try {
      agent.verifyDocumentByIdSync(documentId);
      const storedJson = agent.getDocumentByIdSync(documentId);
      const stored = JSON.parse(storedJson);
      return {
        valid: true,
        signerId: stored?.jacsSignature?.agentID || '',
        timestamp: stored?.jacsSignature?.date || '',
        attachments: extractAttachmentsFromDocument(stored || {}),
        errors: [],
      };
    } catch (e) {
      if (this._strict) throw new Error(`Verification failed (strict mode): ${e}`);
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
    }
  }

  // ---------------------------------------------------------------------------
  // Files
  // ---------------------------------------------------------------------------

  async signFile(filePath: string, embed: boolean = false): Promise<SignedDocument> {
    this.requireAgent();
    if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
    const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
    return this.withPrivateKeyPassword(async (agent) => {
      const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, filePath, embed);
      return parseSignedResult(result);
    });
  }

  signFileSync(filePath: string, embed: boolean = false): SignedDocument {
    this.requireAgent();
    if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
    const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
    return this.withPrivateKeyPasswordSync((agent) => {
      const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, filePath, embed);
      return parseSignedResult(result);
    });
  }

  // ---------------------------------------------------------------------------
  // Agreements
  // ---------------------------------------------------------------------------

  async createAgreement(document: any, agentIds: string[], options?: AgreementOptions): Promise<SignedDocument> {
    const docString = normalizeDocumentInput(document);
    const hasExtended = options?.timeout || options?.quorum !== undefined || options?.requiredAlgorithms || options?.minimumStrength;
    return this.withPrivateKeyPassword(async (agent) => {
      let result: string;
      if (hasExtended) {
        result = await agent.createAgreementWithOptions(
          docString, agentIds, options?.question || null, options?.context || null,
          options?.fieldName || null, options?.timeout || null, options?.quorum ?? null,
          options?.requiredAlgorithms || null, options?.minimumStrength || null,
        );
      } else {
        result = await agent.createAgreement(
          docString, agentIds, options?.question || null, options?.context || null, options?.fieldName || null,
        );
      }
      return parseSignedResult(result);
    });
  }

  createAgreementSync(document: any, agentIds: string[], options?: AgreementOptions): SignedDocument {
    const docString = normalizeDocumentInput(document);
    const hasExtended = options?.timeout || options?.quorum !== undefined || options?.requiredAlgorithms || options?.minimumStrength;
    return this.withPrivateKeyPasswordSync((agent) => {
      let result: string;
      if (hasExtended) {
        result = agent.createAgreementWithOptionsSync(
          docString, agentIds, options?.question || null, options?.context || null,
          options?.fieldName || null, options?.timeout || null, options?.quorum ?? null,
          options?.requiredAlgorithms || null, options?.minimumStrength || null,
        );
      } else {
        result = agent.createAgreementSync(
          docString, agentIds, options?.question || null, options?.context || null, options?.fieldName || null,
        );
      }
      return parseSignedResult(result);
    });
  }

  async signAgreement(document: any, fieldName?: string): Promise<SignedDocument> {
    const docString = normalizeDocumentInput(document);
    return this.withPrivateKeyPassword(async (agent) => {
      const result = await agent.signAgreement(docString, fieldName || null);
      return parseSignedResult(result);
    });
  }

  signAgreementSync(document: any, fieldName?: string): SignedDocument {
    const docString = normalizeDocumentInput(document);
    return this.withPrivateKeyPasswordSync((agent) => {
      const result = agent.signAgreementSync(docString, fieldName || null);
      return parseSignedResult(result);
    });
  }

  async checkAgreement(document: any, fieldName?: string): Promise<AgreementStatus> {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = await agent.checkAgreement(docString, fieldName || null);
    return JSON.parse(result);
  }

  checkAgreementSync(document: any, fieldName?: string): AgreementStatus {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = agent.checkAgreementSync(docString, fieldName || null);
    return JSON.parse(result);
  }

  // ---------------------------------------------------------------------------
  // Agent management
  // ---------------------------------------------------------------------------

  async updateAgent(newAgentData: any): Promise<string> {
    const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return this.withPrivateKeyPassword((agent) => agent.updateAgent(dataString));
  }

  updateAgentSync(newAgentData: any): string {
    const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return this.withPrivateKeyPasswordSync((agent) => agent.updateAgentSync(dataString));
  }

  async updateDocument(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): Promise<SignedDocument> {
    const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
    return this.withPrivateKeyPassword(async (agent) => {
      const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
      return parseSignedResult(result);
    });
  }

  updateDocumentSync(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): SignedDocument {
    const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
    return this.withPrivateKeyPasswordSync((agent) => {
      const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
      return parseSignedResult(result);
    });
  }

  // ---------------------------------------------------------------------------
  // Trust Store (sync-only)
  // ---------------------------------------------------------------------------

  trustAgent(agentJson: string): string { return nativeTrustAgent(agentJson); }
  trustAgentWithKey(agentJson: string, publicKeyPem: string): string {
    if (!publicKeyPem || !publicKeyPem.trim()) {
      throw new Error('publicKeyPem cannot be empty');
    }
    return nativeTrustAgentWithKey(agentJson, publicKeyPem);
  }
  listTrustedAgents(): string[] { return nativeListTrustedAgents(); }
  untrustAgent(agentId: string): void { nativeUntrustAgent(agentId); }
  isTrusted(agentId: string): boolean { return nativeIsTrusted(agentId); }
  getTrustedAgent(agentId: string): string { return nativeGetTrustedAgent(agentId); }

  getPublicKey(): string {
    if (!this.info) {
      throw new Error('No agent loaded. Call quickstart({ name, domain }), ephemeral(), load(), or create() first.');
    }
    const keyPath = this.info.publicKeyPath;
    if (!keyPath || !fs.existsSync(keyPath)) {
      throw new Error(`Public key not found: ${keyPath}`);
    }
    return fs.readFileSync(keyPath, 'utf8');
  }

  exportAgent(): string {
    if (!this.info) {
      throw new Error('No agent loaded. Call quickstart({ name, domain }), ephemeral(), load(), or create() first.');
    }
    const configPath = path.resolve(this.info.configPath);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const dataDir = resolveConfigRelativePath(
      configPath,
      config.jacs_data_directory || './jacs_data',
    );
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const agentPath = path.join(dataDir, 'agent', `${agentIdVersion}.json`);
    if (!fs.existsSync(agentPath)) {
      throw new Error(`Agent file not found: ${agentPath}`);
    }
    return fs.readFileSync(agentPath, 'utf8');
  }

  /** @deprecated Use getPublicKey() instead. */
  sharePublicKey(): string {
    warnDeprecated('sharePublicKey', 'getPublicKey');
    return this.getPublicKey();
  }

  /** @deprecated Use exportAgent() instead. */
  shareAgent(): string {
    warnDeprecated('shareAgent', 'exportAgent');
    return this.exportAgent();
  }

  // ---------------------------------------------------------------------------
  // Verification Link
  // ---------------------------------------------------------------------------

  generateVerifyLink(doc: string, baseUrl?: string): string {
    const encoded = Buffer.from(doc).toString('base64url');
    return `${baseUrl || 'https://hai.ai/jacs/verify'}?s=${encoded}`;
  }

  // ---------------------------------------------------------------------------
  // Audit
  // ---------------------------------------------------------------------------

  async audit(options?: AuditOptions): Promise<Record<string, unknown>> {
    const json = await nativeAudit(options?.configPath ?? undefined, options?.recentN ?? undefined);
    return JSON.parse(json) as Record<string, unknown>;
  }

  auditSync(options?: AuditOptions): Record<string, unknown> {
    const json = nativeAuditSync(options?.configPath ?? undefined, options?.recentN ?? undefined);
    return JSON.parse(json) as Record<string, unknown>;
  }

  // ---------------------------------------------------------------------------
  // Attestation
  // ---------------------------------------------------------------------------

  /**
   * Create a signed attestation document.
   *
   * @param params - Object with subject, claims, and optional evidence/derivation/policyContext.
   * @returns The signed attestation document as a SignedDocument.
   */
  async createAttestation(params: {
    subject: Record<string, unknown>;
    claims: Record<string, unknown>[];
    evidence?: Record<string, unknown>[];
    derivation?: Record<string, unknown>;
    policyContext?: Record<string, unknown>;
  }): Promise<SignedDocument> {
    const paramsJson = JSON.stringify(params);
    return this.withPrivateKeyPassword(async (agent) => {
      const raw: string = await agent.createAttestation(paramsJson);
      return parseSignedResult(raw);
    });
  }

  /**
   * Verify an attestation document.
   *
   * The returned object preserves the canonical wire-format field names from the
   * attestation/DSSE JSON contracts, which use camelCase.
   *
   * @param attestationJson - Raw JSON string of the attestation document.
   * @param opts - Optional. Set full: true for full-tier verification.
   * @returns Verification result with valid, crypto, evidence, chain, errors.
   */
  async verifyAttestation(
    attestationJson: string,
    opts?: { full?: boolean },
  ): Promise<AttestationVerificationResult> {
    const agent = this.requireAgent();
    const doc = JSON.parse(attestationJson);
    const docKey = `${doc.jacsId}:${doc.jacsVersion}`;
    let resultJson: string;
    if (opts?.full) {
      resultJson = await agent.verifyAttestationFull(docKey);
    } else {
      resultJson = await agent.verifyAttestation(docKey);
    }
    return JSON.parse(resultJson) as AttestationVerificationResult;
  }

  /**
   * Lift a signed document into an attestation.
   *
   * @param signedDocJson - Raw JSON string of the signed document.
   * @param claims - Array of claim objects.
   * @returns The lifted attestation as a SignedDocument.
   */
  async liftToAttestation(
    signedDocJson: string,
    claims: Record<string, unknown>[],
  ): Promise<SignedDocument> {
    const claimsJson = JSON.stringify(claims);
    return this.withPrivateKeyPassword(async (agent) => {
      const raw: string = await agent.liftToAttestation(signedDocJson, claimsJson);
      return parseSignedResult(raw);
    });
  }

  /**
   * Export an attestation as a DSSE (Dead Simple Signing Envelope).
   *
   * @param attestationJson - Raw JSON string of the attestation document.
   * @returns The DSSE envelope as a parsed object.
   */
  async exportAttestationDsse(
    attestationJson: string,
  ): Promise<DsseEnvelope> {
    return this.withPrivateKeyPassword(async (agent) => {
      const raw: string = await agent.exportAttestationDsse(attestationJson);
      return JSON.parse(raw) as DsseEnvelope;
    });
  }

  // ---------------------------------------------------------------------------
  // A2A (Agent-to-Agent)
  // ---------------------------------------------------------------------------

  /**
   * Get a configured JACSA2AIntegration instance bound to this client.
   *
   * @example
   * ```typescript
   * const a2a = client.getA2A();
   * const card = a2a.exportAgentCard({ jacsId: client.agentId, ... });
   * const signed = await a2a.signArtifact(artifact, 'task');
   * ```
   */
  getA2A(): any {
    const { JACSA2AIntegration } = require('./a2a');
    return new JACSA2AIntegration(this);
  }

  /**
   * Export this agent as an A2A Agent Card.
   *
   * @param agentData - JACS agent data (jacsId, jacsName, jacsServices, etc.).
   *   If not provided, a minimal card is built from the client's own info.
   */
  exportAgentCard(agentData?: Record<string, unknown>): any {
    const a2a = this.getA2A();
    const data = agentData || {
      jacsId: this.agentId,
      jacsName: this.name,
      jacsDescription: `JACS agent ${this.name || this.agentId}`,
    };
    return a2a.exportAgentCard(data);
  }

  /**
   * Sign an A2A artifact with this agent's JACS provenance.
   *
   * @param artifact - The artifact payload to sign.
   * @param artifactType - Type label (e.g., "task", "message", "result").
   * @param parentSignatures - Optional parent signatures for chain of custody.
   */
  async signArtifact(
    artifact: Record<string, unknown>,
    artifactType: string,
    parentSignatures?: Record<string, unknown>[] | null,
  ): Promise<Record<string, unknown>> {
    const a2a = this.getA2A();
    return a2a.signArtifact(artifact, artifactType, parentSignatures ?? null);
  }

  /**
   * Verify a JACS-signed A2A artifact.
   *
   * Accepts the raw JSON string from signArtifact() or a parsed object.
   * When a string is given it is passed directly to verifyResponse to
   * preserve the original serialization and hash.
   *
   * @param wrappedArtifact - The signed artifact (string or object).
   */
  async verifyArtifact(
    wrappedArtifact: string | Record<string, unknown>,
  ): Promise<ClientArtifactVerificationResult> {
    const agent = this.requireAgent();
    const docString = typeof wrappedArtifact === 'string'
      ? wrappedArtifact
      : JSON.stringify(wrappedArtifact);
    const doc = typeof wrappedArtifact === 'string'
      ? JSON.parse(wrappedArtifact)
      : wrappedArtifact;
    const payload = doc.jacs_payload && typeof doc.jacs_payload === 'object'
      ? doc.jacs_payload as Record<string, unknown>
      : null;

    try {
      const rawVerificationResult = agent.verifyResponse(docString);
      const normalized = normalizeA2AVerificationResult(rawVerificationResult);
      const sig = doc.jacsSignature || {};
      const result: ClientArtifactVerificationResult = {
        valid: normalized.valid,
        verificationResult: normalized.verificationResult,
        signerId: sig.agentID || 'unknown',
        signerVersion: sig.agentVersion || 'unknown',
        artifactType: doc.jacsType || 'unknown',
        timestamp: doc.jacsVersionDate || '',
        originalArtifact: doc.a2aArtifact || payload?.a2aArtifact || {},
      };
      if (normalized.verifiedPayload) {
        result.verifiedPayload = normalized.verifiedPayload;
      }
      return result;
    } catch (e) {
      if (this._strict) throw new Error(`Artifact verification failed (strict mode): ${e}`);
      const sig = doc.jacsSignature || {};
      return {
        valid: false,
        verificationResult: false,
        signerId: sig.agentID || 'unknown',
        signerVersion: sig.agentVersion || 'unknown',
        artifactType: doc.jacsType || 'unknown',
        timestamp: doc.jacsVersionDate || '',
        originalArtifact: doc.a2aArtifact || payload?.a2aArtifact || {},
        error: String(e),
      };
    }
  }

  /**
   * Generate .well-known documents for A2A discovery.
   *
   * @param agentCard - The A2A Agent Card (from exportAgentCard).
   * @param jwsSignature - JWS signature of the Agent Card.
   * @param publicKeyB64 - Base64-encoded public key.
   * @param agentData - JACS agent data for metadata.
   */
  generateWellKnownDocuments(
    agentCard: any,
    jwsSignature: string,
    publicKeyB64: string,
    agentData: Record<string, unknown>,
  ): Record<string, Record<string, unknown>> {
    const a2a = this.getA2A();
    return a2a.generateWellKnownDocuments(agentCard, jwsSignature, publicKeyB64, agentData);
  }
}
