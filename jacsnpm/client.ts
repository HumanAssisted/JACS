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
  JacsSimpleAgent,
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
  quickstartPrivateKeyPassword as nativeQuickstartPrivateKeyPassword,
  resolvePrivateKeyPassword as nativeResolvePrivateKeyPassword,
} from './index';
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

export interface RotationResult {
  jacs_id: string;
  old_version: string;
  new_version: string;
  new_public_key_pem: string;
  new_public_key_hash: string;
  signed_agent_json: string;
  transition_proof: string | null;
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

function resolvePrivateKeyPassword(
  configPath?: string | null,
  keyDirectory?: string | null,
  explicitPassword?: string | null,
): string {
  return nativeResolvePrivateKeyPassword(
    configPath ? path.resolve(configPath) : null,
    keyDirectory ?? null,
    explicitPassword ?? null,
  );
}

function configurePrivateKeyPassword(agent: JacsAgent, password?: string | null): void {
  agent.setPrivateKeyPassword(password ?? null);
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

function parseLoadedAgentInfo(resultJson: string): AgentInfo {
  const info = JSON.parse(resultJson);
  return {
    agentId: info.agent_id || '',
    name: info.name || '',
    publicKeyPath: info.public_key_path || '',
    configPath: info.config_path || '',
    version: info.version || '',
    algorithm: info.algorithm || 'pq2025',
    privateKeyPath: info.private_key_path || '',
    dataDirectory: info.data_directory || '',
    keyDirectory: info.key_directory || '',
    domain: info.domain || '',
    dnsRecord: info.dns_record || '',
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

function ensurePassword(configPath?: string | null, keyDirectory?: string | null): string {
  return nativeQuickstartPrivateKeyPassword(
    configPath ? path.resolve(configPath) : null,
    keyDirectory ?? null,
  );
}

function isConfigNotFoundError(error: unknown): boolean {
  return String(error).toLowerCase().includes('config file not found');
}

/**
 * Best-effort load of an auxiliary `JacsSimpleAgent` from `configPath`.
 *
 * Returns `null` if the load fails (e.g., missing JACS_PRIVATE_KEY_PASSWORD,
 * partial config). The inline-text / image methods then raise at call time
 * with a clear error rather than breaking the broader load/create flow that
 * does not require these features.
 */
function tryLoadSimpleAgent(configPath: string, strict: boolean | undefined): JacsSimpleAgent | null {
  try {
    return JacsSimpleAgent.load(configPath, strict ?? null);
  } catch {
    return null;
  }
}

// =============================================================================
// JacsClient
// =============================================================================

// =============================================================================
// Inline-text / image option types (Task 11)
// =============================================================================

export interface SignTextOptions {
  noBackup?: boolean;
}

export interface VerifyTextOptions {
  /**
   * C1: when true, missing signatures reject the Promise with
   * /no JACS signature found/. Default false.
   */
  strict?: boolean;
  /**
   * PRD §4.1.5: directory of `<signer_id>.public.pem` files for offline
   * verification.
   */
  keyDir?: string;
}

export interface SignImageOptions {
  /**
   * PRD §4.2.4: enable LSB embedding for re-encode survivability
   * (PNG/JPEG only). Default false (Q4).
   */
  robust?: boolean;
  /** Optional explicit format override ("png" | "jpeg" | "webp"). */
  format?: string;
  /**
   * PRD §4.2.2: refuse if the input image already carries a JACS
   * signature.
   */
  refuseOverwrite?: boolean;
}

export interface VerifyImageOptions {
  /** C1: see [VerifyTextOptions.strict]. */
  strict?: boolean;
  /** PRD §4.1.5: see [VerifyTextOptions.keyDir]. */
  keyDir?: string;
  /**
   * PRD §4.2.4: scan the LSB channel as a fallback when the metadata
   * payload is missing. Default false.
   */
  robust?: boolean;
}

export interface ExtractMediaOptions {
  /** PRD §3.2: when true, return base64url wire form. Default false. */
  rawPayload?: boolean;
}

export class JacsClient {
  private agent: JacsAgent | null = null;
  /**
   * Auxiliary `JacsSimpleAgent` used by the inline-text / image methods
   * (signText / verifyText / signImage / verifyImage / extractMediaSignature).
   *
   * `JacsAgent` exposes the broader v0.x API, while these new operations live
   * on `SimpleAgentWrapper` and are surfaced through `JacsSimpleAgent`. We
   * create a separate instance per `JacsClient` so the inline-text/image
   * methods are routable; for ephemeral clients this means JacsAgent and
   * JacsSimpleAgent have distinct keys (acceptable for the smoke-level test
   * coverage in this task — see Task 11 acceptance criteria).
   */
  private simpleAgent: JacsSimpleAgent | null = null;
  private info: AgentInfo | null = null;
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

    try {
      await client.load(configPath);
      return client;
    } catch (error) {
      if (!isConfigNotFoundError(error)) {
        throw error;
      }
    }

    const password = ensurePassword(configPath, paths.keyDirectory);
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

    try {
      client.loadSync(configPath);
      return client;
    } catch (error) {
      if (!isConfigNotFoundError(error)) {
        throw error;
      }
    }

    const password = ensurePassword(configPath, paths.keyDirectory);
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
    client.simpleAgent = JacsSimpleAgent.ephemeral(algorithm ?? null);
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
    client.simpleAgent = JacsSimpleAgent.ephemeral(algorithm ?? null);
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
    const resolvedPassword = resolvePrivateKeyPassword(resolvedConfigPath, null, null);
    this.agent = new JacsAgent();
    configurePrivateKeyPassword(this.agent, resolvedPassword || null);
    const infoJson = await this.agent.loadWithInfo(resolvedConfigPath);
    this.info = parseLoadedAgentInfo(infoJson);
    // Inline-text / image methods route through JacsSimpleAgent. Loading from
    // the same config makes both agents share the same persistent identity.
    // Best-effort: callers without a resolvable password (or running on a
    // partial config) should still get a working JacsClient — the inline-text
    // methods raise at call time instead of breaking the broader load() flow.
    this.simpleAgent = tryLoadSimpleAgent(resolvedConfigPath, this._strict);
    return this.info!;
  }

  loadSync(configPath?: string, options?: LoadOptions): AgentInfo {
    if (options?.strict !== undefined) {
      this._strict = options.strict;
    }
    const requestedPath = configPath || './jacs.config.json';
    const resolvedConfigPath = path.resolve(requestedPath);
    const resolvedPassword = resolvePrivateKeyPassword(resolvedConfigPath, null, null);
    this.agent = new JacsAgent();
    configurePrivateKeyPassword(this.agent, resolvedPassword || null);
    const infoJson = this.agent.loadWithInfoSync(resolvedConfigPath);
    this.info = parseLoadedAgentInfo(infoJson);
    this.simpleAgent = tryLoadSimpleAgent(resolvedConfigPath, this._strict);
    return this.info!;
  }

  async create(options: CreateAgentOptions): Promise<AgentInfo> {
    const resolvedPassword = resolvePrivateKeyPassword(
      options.configPath ?? null,
      options.keyDirectory ?? null,
      options.password ?? null,
    );
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
    this.agent = new JacsAgent();
    configurePrivateKeyPassword(this.agent, resolvedPassword);
    const infoJson = await this.agent.loadWithInfo(path.resolve(cfgPath));
    this.info = parseLoadedAgentInfo(infoJson);
    if (this.info && result.dns_record && !this.info.dnsRecord) {
      this.info.dnsRecord = result.dns_record;
    }
    this.simpleAgent = tryLoadSimpleAgent(path.resolve(cfgPath), this._strict);
    return this.info!;
  }

  createSync(options: CreateAgentOptions): AgentInfo {
    const resolvedPassword = resolvePrivateKeyPassword(
      options.configPath ?? null,
      options.keyDirectory ?? null,
      options.password ?? null,
    );
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
    this.agent = new JacsAgent();
    configurePrivateKeyPassword(this.agent, resolvedPassword);
    const infoJson = this.agent.loadWithInfoSync(path.resolve(cfgPath));
    this.info = parseLoadedAgentInfo(infoJson);
    if (this.info && result.dns_record && !this.info.dnsRecord) {
      this.info.dnsRecord = result.dns_record;
    }
    this.simpleAgent = tryLoadSimpleAgent(path.resolve(cfgPath), this._strict);
    return this.info!;
  }

  reset(): void {
    if (this.agent) {
      try {
        this.agent.setPrivateKeyPassword(null);
      } catch {
        // Best-effort cleanup; the instance is being discarded anyway.
      }
    }
    this.agent = null;
    this.simpleAgent = null;
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
    return operation(agent);
  }

  private withPrivateKeyPasswordSync<T>(operation: (agent: JacsAgent) => T): T {
    const agent = this.requireAgent();
    return operation(agent);
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
    const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
    return this.withPrivateKeyPassword(async (agent) => {
      const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, filePath, embed);
      return parseSignedResult(result);
    });
  }

  signFileSync(filePath: string, embed: boolean = false): SignedDocument {
    this.requireAgent();
    const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
    return this.withPrivateKeyPasswordSync((agent) => {
      const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, filePath, embed);
      return parseSignedResult(result);
    });
  }

  // ---------------------------------------------------------------------------
  // Inline text + image (Task 11 — PRD §3.1, §3.2, §4.1, §4.2)
  // ---------------------------------------------------------------------------

  private requireSimpleAgent(): JacsSimpleAgent {
    if (!this.simpleAgent) {
      throw new Error(
        'No agent loaded. Call ephemeral(), load(), quickstart(), or create() first.',
      );
    }
    return this.simpleAgent;
  }

  /**
   * Sign a text/markdown file in place by appending an inline JACS
   * signature block (PRD §4.1).
   */
  async signText(filePath: string, options?: SignTextOptions): Promise<any> {
    return this.requireSimpleAgent().signText(filePath, options?.noBackup ?? false);
  }

  signTextSync(filePath: string, options?: SignTextOptions): any {
    return this.requireSimpleAgent().signTextSync(filePath, options?.noBackup ?? false);
  }

  /**
   * Verify inline JACS signatures in a text/markdown file (PRD §4.1, C1).
   * In permissive mode (default), missing-signature returns
   * `{ status: 'missing_signature' }`. In strict mode the Promise rejects
   * with `/no JACS signature found/`.
   */
  async verifyText(filePath: string, options?: VerifyTextOptions): Promise<any> {
    return this.requireSimpleAgent().verifyText(filePath, {
      strict: options?.strict ?? false,
      keyDir: options?.keyDir,
    });
  }

  verifyTextSync(filePath: string, options?: VerifyTextOptions): any {
    return this.requireSimpleAgent().verifyTextSync(filePath, {
      strict: options?.strict ?? false,
      keyDir: options?.keyDir,
    });
  }

  /**
   * Sign a PNG / JPEG / WebP image by embedding a JACS signature
   * (PRD §4.2). `outputPath` may equal `inputPath` for in-place writes.
   */
  async signImage(
    inputPath: string,
    outputPath: string,
    options?: SignImageOptions,
  ): Promise<any> {
    return this.requireSimpleAgent().signImage(inputPath, outputPath, {
      robust: options?.robust ?? false,
      format: options?.format,
      refuseOverwrite: options?.refuseOverwrite ?? false,
    });
  }

  signImageSync(inputPath: string, outputPath: string, options?: SignImageOptions): any {
    return this.requireSimpleAgent().signImageSync(inputPath, outputPath, {
      robust: options?.robust ?? false,
      format: options?.format,
      refuseOverwrite: options?.refuseOverwrite ?? false,
    });
  }

  /**
   * Verify an embedded JACS signature in an image (PRD §4.2, C1).
   */
  async verifyImage(filePath: string, options?: VerifyImageOptions): Promise<any> {
    return this.requireSimpleAgent().verifyImage(filePath, {
      strict: options?.strict ?? false,
      keyDir: options?.keyDir,
      robust: options?.robust ?? false,
    });
  }

  verifyImageSync(filePath: string, options?: VerifyImageOptions): any {
    return this.requireSimpleAgent().verifyImageSync(filePath, {
      strict: options?.strict ?? false,
      keyDir: options?.keyDir,
      robust: options?.robust ?? false,
    });
  }

  /**
   * Extract the JACS signature payload embedded in a signed image
   * (PRD §3.2). Returns the decoded JACS signed-document JSON string by
   * default; pass `{ rawPayload: true }` for the base64url wire form.
   * Returns `null` when the input has no JACS signature.
   */
  async extractMediaSignature(
    filePath: string,
    options?: ExtractMediaOptions,
  ): Promise<string | null> {
    return this.requireSimpleAgent().extractMediaSignature(filePath, {
      rawPayload: options?.rawPayload ?? false,
    });
  }

  extractMediaSignatureSync(filePath: string, options?: ExtractMediaOptions): string | null {
    return this.requireSimpleAgent().extractMediaSignatureSync(filePath, {
      rawPayload: options?.rawPayload ?? false,
    });
  }

  // ---------------------------------------------------------------------------
  // Format Conversion (YAML / HTML)
  // ---------------------------------------------------------------------------

  /**
   * Convert a JSON string to YAML.
   */
  async toYaml(jsonStr: string): Promise<string> {
    const agent = this.requireAgent();
    return agent.toYaml(jsonStr);
  }

  toYamlSync(jsonStr: string): string {
    const agent = this.requireAgent();
    return agent.toYamlSync(jsonStr);
  }

  /**
   * Convert a YAML string to pretty-printed JSON.
   */
  async fromYaml(yamlStr: string): Promise<string> {
    const agent = this.requireAgent();
    return agent.fromYaml(yamlStr);
  }

  fromYamlSync(yamlStr: string): string {
    const agent = this.requireAgent();
    return agent.fromYamlSync(yamlStr);
  }

  /**
   * Convert a JSON string to a self-contained HTML document.
   */
  async toHtml(jsonStr: string): Promise<string> {
    const agent = this.requireAgent();
    return agent.toHtml(jsonStr);
  }

  toHtmlSync(jsonStr: string): string {
    const agent = this.requireAgent();
    return agent.toHtmlSync(jsonStr);
  }

  /**
   * Extract JSON from an HTML document produced by toHtml().
   */
  async fromHtml(htmlStr: string): Promise<string> {
    const agent = this.requireAgent();
    return agent.fromHtml(htmlStr);
  }

  fromHtmlSync(htmlStr: string): string {
    const agent = this.requireAgent();
    return agent.fromHtmlSync(htmlStr);
  }

  /**
   * Convert YAML to JSON and verify the resulting document.
   */
  async verifyYaml(yamlStr: string): Promise<boolean> {
    const agent = this.requireAgent();
    return agent.verifyYaml(yamlStr);
  }

  verifyYamlSync(yamlStr: string): boolean {
    const agent = this.requireAgent();
    return agent.verifyYamlSync(yamlStr);
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
    return this.requireAgent().getPublicKeyPem();
  }

  /**
   * Rotate the agent's cryptographic keys.
   *
   * Generates a new keypair, archives the old keys, creates a new agent
   * version, and re-signs the config file.
   *
   * @param options - Optional. `{ algorithm?: string }` to change the signing algorithm.
   * @returns Rotation result with old_version, new_version, transition_proof, etc.
   */
  async rotateKeys(options?: { algorithm?: string }): Promise<RotationResult> {
    const agent = this.requireAgent();
    const resultJson = await agent.rotateKeys(options?.algorithm ?? null);
    return JSON.parse(resultJson) as RotationResult;
  }

  /**
   * Rotate the agent's cryptographic keys (sync variant).
   */
  rotateKeysSync(options?: { algorithm?: string }): RotationResult {
    const agent = this.requireAgent();
    const resultJson = agent.rotateKeysSync(options?.algorithm ?? null);
    return JSON.parse(resultJson) as RotationResult;
  }

  exportAgent(): string {
    return this.requireAgent().exportAgent();
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
   * const signed = await a2a.signArtifact(artifact, 'artifact');
   * ```
   */
  getA2A(): any {
    const { JACSA2AIntegration } = require('./a2a');
    return new JACSA2AIntegration(this);
  }

  /**
   * Export this agent as an A2A Agent Card.
   *
   * @param agentData - A2A agent card data (jacsId, jacsName, skills, etc.).
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
   * @param artifactType - Type label (e.g., "artifact", "result").
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
