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
 * const client = await JacsClient.quickstart({ algorithm: 'ring-Ed25519' });
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
  listTrustedAgents as nativeListTrustedAgents,
  untrustAgent as nativeUntrustAgent,
  isTrusted as nativeIsTrusted,
  getTrustedAgent as nativeGetTrustedAgent,
  auditSync as nativeAuditSync,
  audit as nativeAudit,
} from './index';
import * as fs from 'fs';
import * as path from 'path';

import {
  generateVerifyLink,
  MAX_VERIFY_URL_LEN,
  MAX_VERIFY_DOCUMENT_BYTES,
} from './simple';

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

export { hashString, createConfig, generateVerifyLink, MAX_VERIFY_URL_LEN, MAX_VERIFY_DOCUMENT_BYTES };

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

function extractAgentInfo(resolvedConfigPath: string): AgentInfo {
  const config = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8'));
  const agentIdVersion = config.jacs_agent_id_and_version || '';
  const [agentId] = agentIdVersion.split(':');
  const keyDir = resolveConfigRelativePath(
    resolvedConfigPath,
    config.jacs_key_directory || './jacs_keys',
  );
  return {
    agentId: agentId || '',
    name: config.name || '',
    publicKeyPath: path.join(keyDir, 'jacs.public.pem'),
    configPath: resolvedConfigPath,
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

function ensurePassword(): string {
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
    const keysDir = './jacs_keys';
    fs.mkdirSync(keysDir, { recursive: true });
    const pwPath = path.join(keysDir, '.jacs_password');
    fs.writeFileSync(pwPath, password, { mode: 0o600 });
    process.env.JACS_PRIVATE_KEY_PASSWORD = password;
  }
  return password;
}

// =============================================================================
// JacsClient
// =============================================================================

export class JacsClient {
  private agent: JacsAgent | null = null;
  private info: AgentInfo | null = null;
  private _strict: boolean = false;

  constructor(options?: JacsClientOptions) {
    this._strict = resolveStrict(options?.strict);
  }

  // ---------------------------------------------------------------------------
  // Static factories (async)
  // ---------------------------------------------------------------------------

  /**
   * Zero-config factory: loads or creates a persistent agent.
   */
  static async quickstart(options?: QuickstartOptions): Promise<JacsClient> {
    const client = new JacsClient({ strict: options?.strict });
    const configPath = (options as any)?.configPath || './jacs.config.json';

    if (fs.existsSync(configPath)) {
      await client.load(configPath);
      return client;
    }

    const password = ensurePassword();
    const algo = options?.algorithm || 'pq2025';
    await client.create({ name: 'jacs-agent', password, algorithm: algo, configPath });
    return client;
  }

  /**
   * Zero-config factory (sync variant).
   */
  static quickstartSync(options?: QuickstartOptions): JacsClient {
    const client = new JacsClient({ strict: options?.strict });
    const configPath = (options as any)?.configPath || './jacs.config.json';

    if (fs.existsSync(configPath)) {
      client.loadSync(configPath);
      return client;
    }

    const password = ensurePassword();
    const algo = options?.algorithm || 'pq2025';
    client.createSync({ name: 'jacs-agent', password, algorithm: algo, configPath });
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
    this.agent = new JacsAgent();
    await this.agent.load(resolvedConfigPath);
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
    this.agent = new JacsAgent();
    this.agent.loadSync(resolvedConfigPath);
    this.info = extractAgentInfo(resolvedConfigPath);
    return this.info;
  }

  async create(options: CreateAgentOptions): Promise<AgentInfo> {
    const resolvedPassword = options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
    if (!resolvedPassword) {
      throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
    }
    const resultJson = await nativeCreateAgent(
      options.name, resolvedPassword, options.algorithm ?? null, options.dataDirectory ?? null,
      options.keyDirectory ?? null, options.configPath ?? null, options.agentType ?? null,
      options.description ?? null, options.domain ?? null, options.defaultStorage ?? null,
    );
    const result = JSON.parse(resultJson);
    const cfgPath = result.config_path || options.configPath || './jacs.config.json';
    this.info = {
      agentId: result.agent_id || '',
      name: result.name || options.name,
      publicKeyPath: result.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
      configPath: cfgPath,
    };
    this.agent = new JacsAgent();
    await this.agent.load(path.resolve(cfgPath));
    return this.info;
  }

  createSync(options: CreateAgentOptions): AgentInfo {
    const resolvedPassword = options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
    if (!resolvedPassword) {
      throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
    }
    const resultJson = nativeCreateAgentSync(
      options.name, resolvedPassword, options.algorithm ?? null, options.dataDirectory ?? null,
      options.keyDirectory ?? null, options.configPath ?? null, options.agentType ?? null,
      options.description ?? null, options.domain ?? null, options.defaultStorage ?? null,
    );
    const result = JSON.parse(resultJson);
    const cfgPath = result.config_path || options.configPath || './jacs.config.json';
    this.info = {
      agentId: result.agent_id || '',
      name: result.name || options.name,
      publicKeyPath: result.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
      configPath: cfgPath,
    };
    this.agent = new JacsAgent();
    this.agent.loadSync(path.resolve(cfgPath));
    return this.info;
  }

  reset(): void {
    this.agent = null;
    this.info = null;
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

  // ---------------------------------------------------------------------------
  // Signing & Verification
  // ---------------------------------------------------------------------------

  private requireAgent(): JacsAgent {
    if (!this.agent) {
      throw new Error('No agent loaded. Call quickstart(), ephemeral(), load(), or create() first.');
    }
    return this.agent;
  }

  async signMessage(data: any): Promise<SignedDocument> {
    const agent = this.requireAgent();
    const docContent = { jacsType: 'message', jacsLevel: 'raw', content: data };
    const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, null, null);
    return parseSignedResult(result);
  }

  signMessageSync(data: any): SignedDocument {
    const agent = this.requireAgent();
    const docContent = { jacsType: 'message', jacsLevel: 'raw', content: data };
    const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, null, null);
    return parseSignedResult(result);
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
      const attachments: Attachment[] = (doc.jacsFiles || []).map((f: any) => ({
        filename: f.path || '', mimeType: f.mimetype || 'application/octet-stream',
        hash: f.sha256 || '', embedded: f.embed || false,
        content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
      }));
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
      const attachments: Attachment[] = (doc.jacsFiles || []).map((f: any) => ({
        filename: f.path || '', mimeType: f.mimetype || 'application/octet-stream',
        hash: f.sha256 || '', embedded: f.embed || false,
        content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
      }));
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
      return { valid: true, signerId: '', timestamp: '', attachments: [], errors: [] };
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
      return { valid: true, signerId: '', timestamp: '', attachments: [], errors: [] };
    } catch (e) {
      if (this._strict) throw new Error(`Verification failed (strict mode): ${e}`);
      return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
    }
  }

  // ---------------------------------------------------------------------------
  // Files
  // ---------------------------------------------------------------------------

  async signFile(filePath: string, embed: boolean = false): Promise<SignedDocument> {
    const agent = this.requireAgent();
    if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
    const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
    const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, filePath, embed);
    return parseSignedResult(result);
  }

  signFileSync(filePath: string, embed: boolean = false): SignedDocument {
    const agent = this.requireAgent();
    if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
    const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
    const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, filePath, embed);
    return parseSignedResult(result);
  }

  // ---------------------------------------------------------------------------
  // Agreements
  // ---------------------------------------------------------------------------

  async createAgreement(document: any, agentIds: string[], options?: AgreementOptions): Promise<SignedDocument> {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);
    const hasExtended = options?.timeout || options?.quorum !== undefined || options?.requiredAlgorithms || options?.minimumStrength;
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
  }

  createAgreementSync(document: any, agentIds: string[], options?: AgreementOptions): SignedDocument {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);
    const hasExtended = options?.timeout || options?.quorum !== undefined || options?.requiredAlgorithms || options?.minimumStrength;
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
  }

  async signAgreement(document: any, fieldName?: string): Promise<SignedDocument> {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = await agent.signAgreement(docString, fieldName || null);
    return parseSignedResult(result);
  }

  signAgreementSync(document: any, fieldName?: string): SignedDocument {
    const agent = this.requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = agent.signAgreementSync(docString, fieldName || null);
    return parseSignedResult(result);
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
    const agent = this.requireAgent();
    const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return agent.updateAgent(dataString);
  }

  updateAgentSync(newAgentData: any): string {
    const agent = this.requireAgent();
    const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return agent.updateAgentSync(dataString);
  }

  async updateDocument(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): Promise<SignedDocument> {
    const agent = this.requireAgent();
    const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
    const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
    return parseSignedResult(result);
  }

  updateDocumentSync(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): SignedDocument {
    const agent = this.requireAgent();
    const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
    const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
    return parseSignedResult(result);
  }

  // ---------------------------------------------------------------------------
  // Trust Store (sync-only)
  // ---------------------------------------------------------------------------

  trustAgent(agentJson: string): string { return nativeTrustAgent(agentJson); }
  listTrustedAgents(): string[] { return nativeListTrustedAgents(); }
  untrustAgent(agentId: string): void { nativeUntrustAgent(agentId); }
  isTrusted(agentId: string): boolean { return nativeIsTrusted(agentId); }
  getTrustedAgent(agentId: string): string { return nativeGetTrustedAgent(agentId); }

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
  // Verify Link
  // ---------------------------------------------------------------------------

  generateVerifyLink(document: string, baseUrl?: string): string {
    return generateVerifyLink(document, baseUrl);
  }
}
