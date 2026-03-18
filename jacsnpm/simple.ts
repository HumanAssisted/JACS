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
import { warnDeprecated } from './deprecation';

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

export interface AttestationCryptoVerificationResult {
  signatureValid: boolean;
  hashValid: boolean;
  signerId: string;
  algorithm: string;
}

export interface AttestationEvidenceVerificationResult {
  kind: string;
  digestValid: boolean;
  freshnessValid: boolean;
  detail: string;
}

export interface AttestationChainLink {
  documentId: string;
  valid: boolean;
  detail: string;
}

export interface AttestationChainVerificationResult {
  valid: boolean;
  depth: number;
  maxDepth: number;
  links: AttestationChainLink[];
}

export interface AttestationVerificationResult {
  valid: boolean;
  crypto: AttestationCryptoVerificationResult;
  evidence: AttestationEvidenceVerificationResult[];
  chain?: AttestationChainVerificationResult | null;
  errors: string[];
}

export interface DsseEnvelope {
  payloadType: string;
  payload: string;
  signatures: Array<{
    keyid?: string;
    sig: string;
  }>;
}

// =============================================================================
// Global State
// =============================================================================

let globalAgent: JacsAgent | null = null;
let agentInfo: AgentInfo | null = null;
let strictMode: boolean = false;

function adoptClientState(client: unknown): AgentInfo {
  const state = client as {
    agent: JacsAgent | null;
    info: AgentInfo | null;
    _strict: boolean;
  };
  globalAgent = state.agent ?? null;
  agentInfo = state.info ? { ...state.info } : null;
  strictMode = state._strict ?? strictMode;
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
  }
  return agentInfo;
}

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

async function withAgentPassword<T>(operation: (agent: JacsAgent) => Promise<T>): Promise<T> {
  const agent = requireAgent();
  return operation(agent);
}

function withAgentPasswordSync<T>(operation: (agent: JacsAgent) => T): T {
  const agent = requireAgent();
  return operation(agent);
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

/**
 * Write .gitignore and .dockerignore in the key directory to prevent
 * accidental exposure of private keys and password files.
 */
function writeKeyDirectoryIgnoreFiles(keyDir: string): void {
  const ignoreContent =
    '# JACS private key material -- do NOT commit or ship\n' +
    '*.pem\n*.pem.enc\n.jacs_password\n*.key\n*.key.enc\n';
  fs.mkdirSync(keyDir, { recursive: true });
  const gitignore = path.join(keyDir, '.gitignore');
  if (!fs.existsSync(gitignore)) {
    try {
      fs.writeFileSync(gitignore, ignoreContent);
    } catch (e) {
      // Best-effort; don't fail agent creation
    }
  }
  const dockerignore = path.join(keyDir, '.dockerignore');
  if (!fs.existsSync(dockerignore)) {
    try {
      fs.writeFileSync(dockerignore, ignoreContent);
    } catch (e) {
      // Best-effort; don't fail agent creation
    }
  }
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

/**
 * Quickstart: loads or creates a persistent agent.
 * @returns Promise<QuickstartInfo>
 */
export async function quickstart(options: QuickstartOptions): Promise<QuickstartInfo> {
  const { JacsClient } = require('./client');
  const client = await JacsClient.quickstart(options);
  return toQuickstartInfo(adoptClientState(client));
}

/**
 * Quickstart (sync variant, blocks event loop).
 */
export function quickstartSync(options: QuickstartOptions): QuickstartInfo {
  const { JacsClient } = require('./client');
  const client = JacsClient.quickstartSync(options);
  return toQuickstartInfo(adoptClientState(client));
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
  const p = resolvePrivateKeyPassword(options.configPath ?? null, options.password ?? null);
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
  const normalizedOptions = {
    ...options,
    ...resolveCreatePaths(options.configPath ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null),
  };
  const resultJson = await nativeCreateAgent(...createNativeArgs(normalizedOptions, password));
  return parseCreateResult(resultJson, normalizedOptions);
}

/**
 * Creates a new JACS agent (sync, blocks event loop).
 */
export function createSync(options: CreateAgentOptions): AgentInfo {
  const password = resolveCreatePassword(options);
  const normalizedOptions = {
    ...options,
    ...resolveCreatePaths(options.configPath ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null),
  };
  const resultJson = nativeCreateAgentSync(...createNativeArgs(normalizedOptions, password));
  return parseCreateResult(resultJson, normalizedOptions);
}

/**
 * Loads an existing agent from a configuration file.
 */
export async function load(configPath?: string, options?: LoadOptions): Promise<AgentInfo> {
  const { JacsClient } = require('./client');
  const client = new JacsClient({ strict: options?.strict });
  await client.load(configPath, options);
  return adoptClientState(client);
}

/**
 * Loads an existing agent (sync, blocks event loop).
 */
export function loadSync(configPath?: string, options?: LoadOptions): AgentInfo {
  const { JacsClient } = require('./client');
  const client = new JacsClient({ strict: options?.strict });
  client.loadSync(configPath, options);
  return adoptClientState(client);
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
  const docContent = createRawDocumentPayload('message', { content: data });
  return withAgentPassword(async (agent) => {
    const result = await createDocumentImpl(agent, docContent, null, null, false) as string;
    return parseSignedResult(result);
  });
}

/**
 * Signs arbitrary data (sync, blocks event loop).
 */
export function signMessageSync(data: any): SignedDocument {
  const docContent = createRawDocumentPayload('message', { content: data });
  return withAgentPasswordSync((agent) => {
    const result = createDocumentImpl(agent, docContent, null, null, true) as string;
    return parseSignedResult(result);
  });
}

/**
 * Updates the agent document with new data and re-signs it.
 */
export async function updateAgent(newAgentData: any): Promise<string> {
  return withAgentPassword((agent) => agent.updateAgent(normalizeJsonInput(newAgentData)));
}

/**
 * Updates the agent document (sync, blocks event loop).
 */
export function updateAgentSync(newAgentData: any): string {
  return withAgentPasswordSync((agent) => agent.updateAgentSync(normalizeJsonInput(newAgentData)));
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
  const dataString = normalizeJsonInput(newDocumentData);
  return withAgentPassword(async (agent) => {
    const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
    return parseSignedResult(result);
  });
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
  const dataString = normalizeJsonInput(newDocumentData);
  return withAgentPasswordSync((agent) => {
    const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
    return parseSignedResult(result);
  });
}

/**
 * Signs a file with optional content embedding.
 */
export async function signFile(filePath: string, embed: boolean = false): Promise<SignedDocument> {
  requireAgent();
  ensureFileExists(filePath);

  const docContent = createRawDocumentPayload('file', {
    filename: path.basename(filePath),
  });
  return withAgentPassword(async (agent) => {
    const result = await createDocumentImpl(agent, docContent, filePath, embed, false) as string;
    return parseSignedResult(result);
  });
}

/**
 * Signs a file (sync, blocks event loop).
 */
export function signFileSync(filePath: string, embed: boolean = false): SignedDocument {
  requireAgent();
  ensureFileExists(filePath);

  const docContent = createRawDocumentPayload('file', {
    filename: path.basename(filePath),
  });
  return withAgentPasswordSync((agent) => {
    const result = createDocumentImpl(agent, docContent, filePath, embed, true) as string;
    return parseSignedResult(result);
  });
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
    const storedJson = await agent.getDocumentById(documentId);
    const stored = JSON.parse(storedJson);
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
    const storedJson = agent.getDocumentByIdSync(documentId);
    const stored = JSON.parse(storedJson);
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
  return requireAgent().getPublicKeyPem();
}

export function exportAgent(): string {
  return requireAgent().exportAgent();
}

/** @deprecated Use getPublicKey() instead. */
export function sharePublicKey(): string {
  warnDeprecated('sharePublicKey', 'getPublicKey');
  return getPublicKey();
}

/** @deprecated Use exportAgent() instead. */
export function shareAgent(): string {
  warnDeprecated('shareAgent', 'exportAgent');
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
  if (globalAgent) {
    try {
      globalAgent.setPrivateKeyPassword(null);
    } catch {
      // Best-effort cleanup; the instance is being discarded anyway.
    }
  }
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
  const docString = normalizeDocumentInput(document);
  return withAgentPassword(async (agent) => {
    const result = await agent.createAgreement(docString, agentIds, question || null, context || null, fieldName || null);
    return parseSignedResult(result);
  });
}

export function createAgreementSync(
  document: any,
  agentIds: string[],
  question?: string,
  context?: string,
  fieldName?: string
): SignedDocument {
  const docString = normalizeDocumentInput(document);
  return withAgentPasswordSync((agent) => {
    const result = agent.createAgreementSync(docString, agentIds, question || null, context || null, fieldName || null);
    return parseSignedResult(result);
  });
}

export async function signAgreement(
  document: any,
  fieldName?: string
): Promise<SignedDocument> {
  const docString = normalizeDocumentInput(document);
  return withAgentPassword(async (agent) => {
    const result = await agent.signAgreement(docString, fieldName || null);
    return parseSignedResult(result);
  });
}

export function signAgreementSync(
  document: any,
  fieldName?: string
): SignedDocument {
  const docString = normalizeDocumentInput(document);
  return withAgentPasswordSync((agent) => {
    const result = agent.signAgreementSync(docString, fieldName || null);
    return parseSignedResult(result);
  });
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

// =============================================================================
// Attestation (requires native module built with `attestation` feature)
// =============================================================================

/**
 * Create a signed attestation document (async).
 *
 * Requires the native module to be built with the `attestation` feature.
 * Throws if attestation is not available or if the claims are invalid.
 *
 * @param params - Object with subject, claims, and optional evidence/derivation/policyContext.
 * @returns The signed attestation as a SignedDocument.
 */
export async function createAttestation(params: {
  subject: Record<string, unknown>;
  claims: Record<string, unknown>[];
  evidence?: Record<string, unknown>[];
  derivation?: Record<string, unknown>;
  policyContext?: Record<string, unknown>;
}): Promise<SignedDocument> {
  return withAgentPassword(async (agent) => {
    const raw: string = await (agent as any).createAttestation(JSON.stringify(params));
    const doc = JSON.parse(raw);
    return {
      raw,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  });
}

/**
 * Create a signed attestation document (sync).
 *
 * @param params - Object with subject, claims, and optional evidence/derivation/policyContext.
 * @returns The signed attestation as a SignedDocument.
 */
export function createAttestationSync(params: {
  subject: Record<string, unknown>;
  claims: Record<string, unknown>[];
  evidence?: Record<string, unknown>[];
  derivation?: Record<string, unknown>;
  policyContext?: Record<string, unknown>;
}): SignedDocument {
  return withAgentPasswordSync((agent) => {
    const raw: string = (agent as any).createAttestationSync(JSON.stringify(params));
    const doc = JSON.parse(raw);
    return {
      raw,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  });
}

/**
 * Verify an attestation document -- local tier (async).
 *
 * The returned object preserves the canonical wire-format field names from the
 * attestation/DSSE JSON contracts, which use camelCase.
 *
 * @param attestationJson - Raw JSON string of the attestation document.
 * @param opts - Optional. Set full: true for full-tier verification.
 * @returns Verification result object.
 */
export async function verifyAttestation(
  attestationJson: string,
  opts?: { full?: boolean },
): Promise<AttestationVerificationResult> {
  const agent = requireAgent();
  const doc = JSON.parse(attestationJson);
  const docKey = `${doc.jacsId}:${doc.jacsVersion}`;
  let resultJson: string;
  if (opts?.full) {
    resultJson = await (agent as any).verifyAttestationFull(docKey);
  } else {
    resultJson = await (agent as any).verifyAttestation(docKey);
  }
  return JSON.parse(resultJson) as AttestationVerificationResult;
}

/**
 * Verify an attestation document -- local tier (sync).
 *
 * The returned object preserves the canonical wire-format field names from the
 * attestation/DSSE JSON contracts, which use camelCase.
 *
 * @param attestationJson - Raw JSON string of the attestation document.
 * @param opts - Optional. Set full: true for full-tier verification.
 * @returns Verification result object.
 */
export function verifyAttestationSync(
  attestationJson: string,
  opts?: { full?: boolean },
): AttestationVerificationResult {
  const agent = requireAgent();
  const doc = JSON.parse(attestationJson);
  const docKey = `${doc.jacsId}:${doc.jacsVersion}`;
  let resultJson: string;
  if (opts?.full) {
    resultJson = (agent as any).verifyAttestationFullSync(docKey);
  } else {
    resultJson = (agent as any).verifyAttestationSync(docKey);
  }
  return JSON.parse(resultJson) as AttestationVerificationResult;
}

/**
 * Lift a signed document into an attestation (async).
 *
 * @param signedDocJson - Raw JSON string of the signed document.
 * @param claims - Array of claim objects.
 * @returns The lifted attestation as a SignedDocument.
 */
export async function liftToAttestation(
  signedDocJson: string,
  claims: Record<string, unknown>[],
): Promise<SignedDocument> {
  return withAgentPassword(async (agent) => {
    const raw: string = await (agent as any).liftToAttestation(signedDocJson, JSON.stringify(claims));
    const doc = JSON.parse(raw);
    return {
      raw,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  });
}

/**
 * Lift a signed document into an attestation (sync).
 *
 * @param signedDocJson - Raw JSON string of the signed document.
 * @param claims - Array of claim objects.
 * @returns The lifted attestation as a SignedDocument.
 */
export function liftToAttestationSync(
  signedDocJson: string,
  claims: Record<string, unknown>[],
): SignedDocument {
  return withAgentPasswordSync((agent) => {
    const raw: string = (agent as any).liftToAttestationSync(signedDocJson, JSON.stringify(claims));
    const doc = JSON.parse(raw);
    return {
      raw,
      documentId: doc.jacsId || '',
      agentId: doc.jacsSignature?.agentID || '',
      timestamp: doc.jacsSignature?.date || '',
    };
  });
}

/**
 * Export an attestation as a DSSE (Dead Simple Signing Envelope) (async).
 *
 * @param attestationJson - Raw JSON string of the attestation document.
 * @returns The DSSE envelope as a parsed object.
 */
export async function exportAttestationDsse(
  attestationJson: string,
): Promise<DsseEnvelope> {
  return withAgentPassword(async (agent) => {
    const raw: string = await (agent as any).exportAttestationDsse(attestationJson);
    return JSON.parse(raw) as DsseEnvelope;
  });
}

/**
 * Export an attestation as a DSSE (Dead Simple Signing Envelope) (sync).
 *
 * @param attestationJson - Raw JSON string of the attestation document.
 * @returns The DSSE envelope as a parsed object.
 */
export function exportAttestationDsseSync(
  attestationJson: string,
): DsseEnvelope {
  return withAgentPasswordSync((agent) => {
    const raw: string = (agent as any).exportAttestationDsseSync(attestationJson);
    return JSON.parse(raw) as DsseEnvelope;
  });
}

// =============================================================================
// Verification Link
// =============================================================================

export function generateVerifyLink(doc: string, baseUrl?: string): string {
  const encoded = Buffer.from(doc).toString('base64url');
  return `${baseUrl || 'https://hai.ai/jacs/verify'}?s=${encoded}`;
}
