/**
 * JACS Simplified API for TypeScript/JavaScript
 *
 * v0.7.0: Async-first API. All functions that call native JACS operations
 * return Promises by default. Use `*Sync` variants when you need synchronous
 * execution (e.g., CLI scripts, initialization code).
 *
 * @example
 * ```typescript
 * import * as jacs from '@hai.ai/jacs/simple';
 *
 * // Load agent (async, default)
 * const agent = await jacs.load('./jacs.config.json');
 *
 * // Sign a message
 * const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
 *
 * // Verify it
 * const result = await jacs.verify(signed.raw);
 * console.log(`Valid: ${result.valid}`);
 *
 * // Sync variants also available
 * const hash = jacs.hashString('data to hash');
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
  verifyDocumentStandalone as nativeVerifyDocumentStandalone,
  auditSync as nativeAuditSync,
  audit as nativeAudit,
} from './index';
import * as fs from 'fs';
import * as path from 'path';

// =============================================================================
// Re-exports for advanced usage
// =============================================================================

export { JacsAgent, hashString, createConfig };

// =============================================================================
// Types
// =============================================================================

export interface AgentInfo {
  agentId: string;
  name: string;
  publicKeyPath: string;
  configPath: string;
  version?: string;
  algorithm?: string;
  privateKeyPath?: string;
  dataDirectory?: string;
  keyDirectory?: string;
  domain?: string;
  dnsRecord?: string;
}

export interface SignedDocument {
  raw: string;
  documentId: string;
  agentId: string;
  timestamp: string;
}

export interface VerificationResult {
  valid: boolean;
  data?: any;
  signerId: string;
  signerName?: string;
  timestamp: string;
  attachments: Attachment[];
  errors: string[];
}

export interface Attachment {
  filename: string;
  mimeType: string;
  content?: Buffer;
  hash: string;
  embedded: boolean;
}

// =============================================================================
// Global State
// =============================================================================

let globalAgent: JacsAgent | null = null;
let agentInfo: AgentInfo | null = null;
let strictMode: boolean = false;

export interface LoadOptions {
  strict?: boolean;
}

function resolveStrict(explicit?: boolean): boolean {
  if (explicit !== undefined) {
    return explicit;
  }
  const envStrict = process.env.JACS_STRICT_MODE;
  return envStrict === 'true' || envStrict === '1';
}

export function isStrict(): boolean {
  return strictMode;
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

function normalizeJsonInput(value: any): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function resolveLoadPath(configPath?: string, options?: LoadOptions): string {
  strictMode = resolveStrict(options?.strict);
  const requestedPath = configPath || './jacs.config.json';
  const resolvedConfigPath = path.resolve(requestedPath);

  if (!fs.existsSync(resolvedConfigPath)) {
    throw new Error(
      `Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`
    );
  }

  return resolvedConfigPath;
}

function setLoadedAgentInfo(resolvedConfigPath: string): AgentInfo {
  agentInfo = extractAgentInfo(resolvedConfigPath);
  return agentInfo;
}

function requireQuickstartIdentity(options: QuickstartOptions | undefined): { name: string; domain: string; description: string } {
  if (!options || typeof options !== 'object') {
    throw new Error('quickstart() requires options.name and options.domain.');
  }

  const name = typeof options.name === 'string' ? options.name.trim() : '';
  const domain = typeof options.domain === 'string' ? options.domain.trim() : '';
  if (!name) {
    throw new Error('quickstart() requires options.name.');
  }
  if (!domain) {
    throw new Error('quickstart() requires options.domain.');
  }
  return {
    name,
    domain,
    description: options.description?.trim() || '',
  };
}

function toQuickstartInfo(info: AgentInfo): QuickstartInfo {
  return {
    agentId: info.agentId,
    name: info.name || '',
    version: info.version || '',
    algorithm: info.algorithm || '',
    configPath: info.configPath || '',
    keyDirectory: info.keyDirectory || '',
    dataDirectory: info.dataDirectory || '',
    publicKeyPath: info.publicKeyPath || '',
    privateKeyPath: info.privateKeyPath || '',
    domain: info.domain || '',
  };
}

function createRawDocumentPayload(
  jacsType: 'message' | 'file',
  extra: Record<string, unknown>
): string {
  return JSON.stringify({
    jacsType,
    jacsLevel: 'raw',
    ...extra,
  });
}

function ensureFileExists(filePath: string): void {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
}

function createDocumentImpl(
  agent: JacsAgent,
  docContent: string,
  filePath: string | null,
  embed: boolean | null,
  isSync: boolean
): string | Promise<string> {
  if (isSync) {
    return agent.createDocumentSync(docContent, null, null, true, filePath, embed);
  }
  return agent.createDocument(docContent, null, null, true, filePath, embed);
}

function makeVerificationSuccess(signerId: string = ''): VerificationResult {
  return {
    valid: true,
    signerId,
    timestamp: '',
    attachments: [],
    errors: [],
  };
}

function makeVerificationFailure(e: any, strictPrefix: string, signerId: string = ''): VerificationResult {
  if (strictMode) {
    throw new Error(`${strictPrefix} (strict mode): ${e}`);
  }
  return {
    valid: false,
    signerId,
    timestamp: '',
    attachments: [],
    errors: [String(e)],
  };
}

function invalidDocumentIdResult(documentId: string): VerificationResult {
  return {
    valid: false,
    signerId: '',
    timestamp: '',
    attachments: [],
    errors: [
      `Document ID must be in 'uuid:version' format, got '${documentId}'. Use verify() with the full JSON string instead.`
    ],
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

function readStoredDocumentById(documentId: string): any | null {
  if (!agentInfo) {
    return null;
  }
  try {
    const configPath = path.resolve(agentInfo.configPath);
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

function parseCreateResult(resultJson: string, options: CreateAgentOptions): AgentInfo {
  const info = JSON.parse(resultJson);
  const configPath = info.config_path || options.configPath || './jacs.config.json';
  const dataDirectory = info.data_directory || options.dataDirectory || './jacs_data';
  const keyDirectory = info.key_directory || options.keyDirectory || './jacs_keys';
  const publicKeyPath = info.public_key_path || `${keyDirectory}/jacs.public.pem`;
  const privateKeyPath = info.private_key_path || `${keyDirectory}/jacs.private.pem.enc`;
  return {
    agentId: info.agent_id || '',
    name: info.name || options.name,
    publicKeyPath,
    configPath,
    version: info.version || '',
    algorithm: info.algorithm || options.algorithm || 'pq2025',
    privateKeyPath,
    dataDirectory,
    keyDirectory,
    domain: info.domain || options.domain || '',
    dnsRecord: info.dns_record || '',
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

function requireAgent(): JacsAgent {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
  }
  return globalAgent;
}

function verifyImpl(signedDocument: string, agent: JacsAgent, isSync: boolean): VerificationResult | Promise<VerificationResult> {
  const trimmed = signedDocument.trim();
  if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    const result: VerificationResult = {
      valid: false,
      signerId: '',
      timestamp: '',
      attachments: [],
      errors: [
        `Input does not appear to be a JSON document. If you have a document ID (e.g., 'uuid:version'), use verifyById() instead. Received: '${trimmed.substring(0, 50)}${trimmed.length > 50 ? '...' : ''}'`
      ],
    };
    return isSync ? result : Promise.resolve(result);
  }

  let doc: any;
  try {
    doc = JSON.parse(signedDocument);
  } catch (e) {
    const result: VerificationResult = {
      valid: false,
      signerId: '',
      timestamp: '',
      attachments: [],
      errors: [`Invalid JSON: ${e}`],
    };
    return isSync ? result : Promise.resolve(result);
  }

  const extractAttachments = () => extractAttachmentsFromDocument(doc);

  const makeSuccess = (): VerificationResult => ({
    valid: true,
    data: doc.content,
    signerId: doc.jacsSignature?.agentID || '',
    timestamp: doc.jacsSignature?.date || '',
    attachments: extractAttachments(),
    errors: [],
  });

  const makeFailure = (e: any): VerificationResult => {
    if (strictMode) {
      throw new Error(`Verification failed (strict mode): ${e}`);
    }
    return {
      valid: false,
      signerId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
      attachments: [],
      errors: [String(e)],
    };
  };

  if (isSync) {
    try {
      agent.verifyDocumentSync(signedDocument);
      return makeSuccess();
    } catch (e) {
      return makeFailure(e);
    }
  } else {
    return agent.verifyDocument(signedDocument)
      .then(() => makeSuccess())
      .catch((e: any) => makeFailure(e));
  }
}

// =============================================================================
// Quickstart
// =============================================================================

export interface QuickstartOptions {
  // Required.
  name: string;
  // Required.
  domain: string;
  description?: string;
  algorithm?: string;
  strict?: boolean;
  configPath?: string;
}

export interface QuickstartInfo {
  agentId: string;
  name: string;
  version: string;
  algorithm: string;
  configPath: string;
  keyDirectory: string;
  dataDirectory: string;
  publicKeyPath: string;
  privateKeyPath: string;
  domain: string;
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

    const persistPassword =
      process.env.JACS_SAVE_PASSWORD_FILE === '1' ||
      process.env.JACS_SAVE_PASSWORD_FILE === 'true';
    if (persistPassword) {
      const keysDir = './jacs_keys';
      fs.mkdirSync(keysDir, { recursive: true });
      const pwPath = path.join(keysDir, '.jacs_password');
      fs.writeFileSync(pwPath, password, { mode: 0o600 });
    }
    process.env.JACS_PRIVATE_KEY_PASSWORD = password;
  }
  return password;
}

/**
 * Quickstart: loads or creates a persistent agent.
 * @returns Promise<QuickstartInfo>
 */
export async function quickstart(options: QuickstartOptions): Promise<QuickstartInfo> {
  const { name, domain, description } = requireQuickstartIdentity(options);
  strictMode = resolveStrict(options?.strict);
  const configPath = options?.configPath || './jacs.config.json';

  if (fs.existsSync(configPath)) {
    const info = await load(configPath);
    return toQuickstartInfo(info);
  }

  const password = ensurePassword();
  const algo = options?.algorithm || 'pq2025';
  await create({
    name,
    password,
    algorithm: algo,
    description,
    domain,
    configPath,
  });
  const loaded = await load(configPath, { strict: strictMode });
  return toQuickstartInfo(loaded);
}

/**
 * Quickstart (sync variant, blocks event loop).
 */
export function quickstartSync(options: QuickstartOptions): QuickstartInfo {
  const { name, domain, description } = requireQuickstartIdentity(options);
  strictMode = resolveStrict(options?.strict);
  const configPath = options?.configPath || './jacs.config.json';

  if (fs.existsSync(configPath)) {
    const info = loadSync(configPath);
    return toQuickstartInfo(info);
  }

  const password = ensurePassword();
  const algo = options?.algorithm || 'pq2025';
  createSync({
    name,
    password,
    algorithm: algo,
    description,
    domain,
    configPath,
  });
  const loaded = loadSync(configPath, { strict: strictMode });
  return toQuickstartInfo(loaded);
}

// =============================================================================
// Core Operations
// =============================================================================

export interface CreateAgentOptions {
  name: string;
  password?: string;
  algorithm?: string;
  dataDirectory?: string;
  keyDirectory?: string;
  configPath?: string;
  agentType?: string;
  description?: string;
  domain?: string;
  defaultStorage?: string;
}

function resolveCreatePassword(options: CreateAgentOptions): string {
  const p = options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
  if (!p) {
    throw new Error(
      'Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.',
    );
  }
  return p;
}

function createNativeArgs(options: CreateAgentOptions, password: string): [string, string, string | null, string | null, string | null, string | null, string | null, string | null, string | null, string | null] {
  return [
    options.name,
    password,
    options.algorithm ?? null,
    options.dataDirectory ?? null,
    options.keyDirectory ?? null,
    options.configPath ?? null,
    options.agentType ?? null,
    options.description ?? null,
    options.domain ?? null,
    options.defaultStorage ?? null,
  ];
}

/**
 * Creates a new JACS agent with cryptographic keys.
 */
export async function create(options: CreateAgentOptions): Promise<AgentInfo> {
  const password = resolveCreatePassword(options);
  const resultJson = await nativeCreateAgent(...createNativeArgs(options, password));
  return parseCreateResult(resultJson, options);
}

/**
 * Creates a new JACS agent (sync, blocks event loop).
 */
export function createSync(options: CreateAgentOptions): AgentInfo {
  const password = resolveCreatePassword(options);
  const resultJson = nativeCreateAgentSync(...createNativeArgs(options, password));
  return parseCreateResult(resultJson, options);
}

/**
 * Loads an existing agent from a configuration file.
 */
export async function load(configPath?: string, options?: LoadOptions): Promise<AgentInfo> {
  const resolvedConfigPath = resolveLoadPath(configPath, options);

  globalAgent = new JacsAgent();
  await globalAgent.load(resolvedConfigPath);
  return setLoadedAgentInfo(resolvedConfigPath);
}

/**
 * Loads an existing agent (sync, blocks event loop).
 */
export function loadSync(configPath?: string, options?: LoadOptions): AgentInfo {
  const resolvedConfigPath = resolveLoadPath(configPath, options);

  globalAgent = new JacsAgent();
  globalAgent.loadSync(resolvedConfigPath);
  return setLoadedAgentInfo(resolvedConfigPath);
}

/**
 * Verifies the currently loaded agent's integrity.
 */
export async function verifySelf(): Promise<VerificationResult> {
  const agent = requireAgent();

  try {
    await agent.verifyAgent();
    return makeVerificationSuccess(agentInfo?.agentId || '');
  } catch (e) {
    return makeVerificationFailure(e, 'Self-verification failed');
  }
}

/**
 * Verifies the currently loaded agent's integrity (sync).
 */
export function verifySelfSync(): VerificationResult {
  const agent = requireAgent();

  try {
    agent.verifyAgentSync();
    return makeVerificationSuccess(agentInfo?.agentId || '');
  } catch (e) {
    return makeVerificationFailure(e, 'Self-verification failed');
  }
}

/**
 * Signs arbitrary data as a JACS message.
 */
export async function signMessage(data: any): Promise<SignedDocument> {
  const agent = requireAgent();
  const docContent = createRawDocumentPayload('message', { content: data });
  const result = await createDocumentImpl(agent, docContent, null, null, false) as string;
  return parseSignedResult(result);
}

/**
 * Signs arbitrary data (sync, blocks event loop).
 */
export function signMessageSync(data: any): SignedDocument {
  const agent = requireAgent();
  const docContent = createRawDocumentPayload('message', { content: data });
  const result = createDocumentImpl(agent, docContent, null, null, true) as string;
  return parseSignedResult(result);
}

/**
 * Updates the agent document with new data and re-signs it.
 */
export async function updateAgent(newAgentData: any): Promise<string> {
  const agent = requireAgent();
  return agent.updateAgent(normalizeJsonInput(newAgentData));
}

/**
 * Updates the agent document (sync, blocks event loop).
 */
export function updateAgentSync(newAgentData: any): string {
  const agent = requireAgent();
  return agent.updateAgentSync(normalizeJsonInput(newAgentData));
}

/**
 * Updates an existing document with new data and re-signs it.
 */
export async function updateDocument(
  documentId: string,
  newDocumentData: any,
  attachments?: string[],
  embed?: boolean
): Promise<SignedDocument> {
  const agent = requireAgent();
  const dataString = normalizeJsonInput(newDocumentData);
  const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
  return parseSignedResult(result);
}

/**
 * Updates an existing document (sync, blocks event loop).
 */
export function updateDocumentSync(
  documentId: string,
  newDocumentData: any,
  attachments?: string[],
  embed?: boolean
): SignedDocument {
  const agent = requireAgent();
  const dataString = normalizeJsonInput(newDocumentData);
  const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
  return parseSignedResult(result);
}

/**
 * Signs a file with optional content embedding.
 */
export async function signFile(filePath: string, embed: boolean = false): Promise<SignedDocument> {
  const agent = requireAgent();
  ensureFileExists(filePath);

  const docContent = createRawDocumentPayload('file', {
    filename: path.basename(filePath),
  });
  const result = await createDocumentImpl(agent, docContent, filePath, embed, false) as string;
  return parseSignedResult(result);
}

/**
 * Signs a file (sync, blocks event loop).
 */
export function signFileSync(filePath: string, embed: boolean = false): SignedDocument {
  const agent = requireAgent();
  ensureFileExists(filePath);

  const docContent = createRawDocumentPayload('file', {
    filename: path.basename(filePath),
  });
  const result = createDocumentImpl(agent, docContent, filePath, embed, true) as string;
  return parseSignedResult(result);
}

/**
 * Verifies a signed document and extracts its content.
 */
export async function verify(signedDocument: string): Promise<VerificationResult> {
  const agent = requireAgent();
  return verifyImpl(signedDocument, agent, false) as Promise<VerificationResult>;
}

/**
 * Verifies a signed document (sync, blocks event loop).
 */
export function verifySync(signedDocument: string): VerificationResult {
  const agent = requireAgent();
  return verifyImpl(signedDocument, agent, true) as VerificationResult;
}

/**
 * Verify a signed JACS document without loading an agent.
 */
export function verifyStandalone(
  signedDocument: string,
  options?: { keyResolution?: string; dataDirectory?: string; keyDirectory?: string }
): VerificationResult {
  const doc = typeof signedDocument === 'string' ? signedDocument : JSON.stringify(signedDocument);
  const r = nativeVerifyDocumentStandalone(
    doc,
    options?.keyResolution ?? undefined,
    options?.dataDirectory ?? undefined,
    options?.keyDirectory ?? undefined
  );
  return {
    valid: r.valid,
    signerId: r.signerId,
    timestamp: r.timestamp || '',
    attachments: [],
    errors: [],
  };
}

/**
 * Verifies a document by its storage ID.
 */
export async function verifyById(documentId: string): Promise<VerificationResult> {
  const agent = requireAgent();

  if (!documentId.includes(':')) {
    return invalidDocumentIdResult(documentId);
  }

  try {
    await agent.verifyDocumentById(documentId);
    const stored = readStoredDocumentById(documentId);
    return {
      ...makeVerificationSuccess(stored?.jacsSignature?.agentID || ''),
      timestamp: stored?.jacsSignature?.date || '',
      attachments: extractAttachmentsFromDocument(stored || {}),
    };
  } catch (e) {
    return makeVerificationFailure(e, 'Verification failed');
  }
}

/**
 * Verifies a document by its storage ID (sync, blocks event loop).
 */
export function verifyByIdSync(documentId: string): VerificationResult {
  const agent = requireAgent();

  if (!documentId.includes(':')) {
    return invalidDocumentIdResult(documentId);
  }

  try {
    agent.verifyDocumentByIdSync(documentId);
    const stored = readStoredDocumentById(documentId);
    return {
      ...makeVerificationSuccess(stored?.jacsSignature?.agentID || ''),
      timestamp: stored?.jacsSignature?.date || '',
      attachments: extractAttachmentsFromDocument(stored || {}),
    };
  } catch (e) {
    return makeVerificationFailure(e, 'Verification failed');
  }
}

/**
 * Re-encrypt the agent's private key with a new password.
 */
export async function reencryptKey(oldPassword: string, newPassword: string): Promise<void> {
  const agent = requireAgent();
  await agent.reencryptKey(oldPassword, newPassword);
}

/**
 * Re-encrypt the agent's private key (sync, blocks event loop).
 */
export function reencryptKeySync(oldPassword: string, newPassword: string): void {
  const agent = requireAgent();
  agent.reencryptKeySync(oldPassword, newPassword);
}

// =============================================================================
// Pure sync helpers (no NAPI calls, stay sync-only)
// =============================================================================

export function getPublicKey(): string {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
  }
  if (!fs.existsSync(agentInfo.publicKeyPath)) {
    throw new Error(`Public key not found: ${agentInfo.publicKeyPath}`);
  }
  return fs.readFileSync(agentInfo.publicKeyPath, 'utf8');
}

export function exportAgent(): string {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
  }
  const configPath = path.resolve(agentInfo.configPath);
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

export function sharePublicKey(): string {
  return getPublicKey();
}

export function shareAgent(): string {
  return exportAgent();
}

export function getAgentInfo(): AgentInfo | null {
  return agentInfo;
}

export function isLoaded(): boolean {
  return globalAgent !== null;
}

export function debugInfo(): Record<string, unknown> {
  if (!globalAgent) {
    return { jacs_version: 'unknown', agent_loaded: false };
  }
  try {
    return JSON.parse(globalAgent.diagnostics());
  } catch {
    return { jacs_version: 'unknown', agent_loaded: false };
  }
}

export function reset(): void {
  globalAgent = null;
  agentInfo = null;
  strictMode = false;
}

export function getDnsRecord(domain: string, ttl: number = 3600): string {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
  }
  const agentDoc = JSON.parse(exportAgent());
  const jacsId = agentDoc.jacsId || agentDoc.agentId || '';
  const publicKeyHash =
    agentDoc.jacsSignature?.publicKeyHash ||
    agentDoc.jacsSignature?.['publicKeyHash'] ||
    '';
  const d = domain.replace(/\.$/, '');
  const owner = `_v1.agent.jacs.${d}.`;
  const txt = `v=jacs; jacs_agent_id=${jacsId}; alg=SHA-256; enc=base64; jac_public_key_hash=${publicKeyHash}`;
  return `${owner} ${ttl} IN TXT "${txt}"`;
}

export function getWellKnownJson(): {
  publicKey: string;
  publicKeyHash: string;
  algorithm: string;
  agentId: string;
} {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
  }
  const agentDoc = JSON.parse(exportAgent());
  const jacsId = agentDoc.jacsId || agentDoc.agentId || '';
  const publicKeyHash =
    agentDoc.jacsSignature?.publicKeyHash ||
    agentDoc.jacsSignature?.['publicKeyHash'] ||
    '';
  let publicKey = '';
  try {
    publicKey = getPublicKey();
  } catch {
    // optional if key file missing
  }
  return {
    publicKey,
    publicKeyHash,
    algorithm: 'SHA-256',
    agentId: jacsId,
  };
}

// =============================================================================
// Setup Instructions
// =============================================================================

export async function getSetupInstructions(
  domain: string,
  ttl: number = 3600,
): Promise<Record<string, unknown>> {
  const agent = requireAgent();
  const json = await agent.getSetupInstructions(domain, ttl);
  return JSON.parse(json) as Record<string, unknown>;
}

export function getSetupInstructionsSync(
  domain: string,
  ttl: number = 3600,
): Record<string, unknown> {
  const agent = requireAgent();
  const json = agent.getSetupInstructionsSync(domain, ttl);
  return JSON.parse(json) as Record<string, unknown>;
}

// =============================================================================
// Agreement Functions
// =============================================================================

export interface AgreementStatus {
  complete: boolean;
  signers: Array<{
    agentId: string;
    signed: boolean;
    signedAt?: string;
  }>;
  pending: string[];
}

export async function createAgreement(
  document: any,
  agentIds: string[],
  question?: string,
  context?: string,
  fieldName?: string
): Promise<SignedDocument> {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = await agent.createAgreement(docString, agentIds, question || null, context || null, fieldName || null);
  return parseSignedResult(result);
}

export function createAgreementSync(
  document: any,
  agentIds: string[],
  question?: string,
  context?: string,
  fieldName?: string
): SignedDocument {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = agent.createAgreementSync(docString, agentIds, question || null, context || null, fieldName || null);
  return parseSignedResult(result);
}

export async function signAgreement(
  document: any,
  fieldName?: string
): Promise<SignedDocument> {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = await agent.signAgreement(docString, fieldName || null);
  return parseSignedResult(result);
}

export function signAgreementSync(
  document: any,
  fieldName?: string
): SignedDocument {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = agent.signAgreementSync(docString, fieldName || null);
  return parseSignedResult(result);
}

export async function checkAgreement(
  document: any,
  fieldName?: string
): Promise<AgreementStatus> {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = await agent.checkAgreement(docString, fieldName || null);
  return JSON.parse(result);
}

export function checkAgreementSync(
  document: any,
  fieldName?: string
): AgreementStatus {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = agent.checkAgreementSync(docString, fieldName || null);
  return JSON.parse(result);
}

// =============================================================================
// Trust Store Functions (sync-only — fast local file lookups)
// =============================================================================

export function trustAgent(agentJson: string): string {
  return nativeTrustAgent(agentJson);
}

export function trustAgentWithKey(agentJson: string, publicKeyPem: string): string {
  if (!publicKeyPem || !publicKeyPem.trim()) {
    throw new Error('publicKeyPem cannot be empty');
  }
  return nativeTrustAgentWithKey(agentJson, publicKeyPem);
}

export function listTrustedAgents(): string[] {
  return nativeListTrustedAgents();
}

export function untrustAgent(agentId: string): void {
  nativeUntrustAgent(agentId);
}

export function isTrusted(agentId: string): boolean {
  return nativeIsTrusted(agentId);
}

export function getTrustedAgent(agentId: string): string {
  return nativeGetTrustedAgent(agentId);
}

// =============================================================================
// Audit
// =============================================================================

export interface AuditOptions {
  configPath?: string;
  recentN?: number;
}

export async function audit(options?: AuditOptions): Promise<Record<string, unknown>> {
  const json = await nativeAudit(options?.configPath ?? undefined, options?.recentN ?? undefined);
  return JSON.parse(json) as Record<string, unknown>;
}

export function auditSync(options?: AuditOptions): Record<string, unknown> {
  const json = nativeAuditSync(options?.configPath ?? undefined, options?.recentN ?? undefined);
  return JSON.parse(json) as Record<string, unknown>;
}
