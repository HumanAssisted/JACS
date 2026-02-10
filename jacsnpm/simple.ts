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

export interface HaiRegistrationOptions {
  apiKey?: string;
  haiUrl?: string;
  preview?: boolean;
}

export interface HaiRegistrationResult {
  agentId: string;
  jacsId: string;
  dnsVerified: boolean;
  signatures: string[];
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

function parseCreateResult(resultJson: string, options: CreateAgentOptions): AgentInfo {
  const info = JSON.parse(resultJson);
  return {
    agentId: info.agent_id || '',
    name: info.name || options.name,
    publicKeyPath: info.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
    configPath: info.config_path || options.configPath || './jacs.config.json',
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
    throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
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

  const extractAttachments = () => (doc.jacsFiles || []).map((f: any) => ({
    filename: f.path || '',
    mimeType: f.mimetype || 'application/octet-stream',
    hash: f.sha256 || '',
    embedded: f.embed || false,
    content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
  }));

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
  algorithm?: string;
  strict?: boolean;
  configPath?: string;
}

export interface QuickstartInfo {
  agentId: string;
  name: string;
  version: string;
  algorithm: string;
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

/**
 * Zero-config quickstart: loads or creates a persistent agent.
 * @returns Promise<QuickstartInfo>
 */
export async function quickstart(options?: QuickstartOptions): Promise<QuickstartInfo> {
  strictMode = resolveStrict(options?.strict);
  const configPath = options?.configPath || './jacs.config.json';

  if (fs.existsSync(configPath)) {
    const info = await load(configPath);
    return {
      agentId: info.agentId,
      name: info.name || 'jacs-agent',
      version: '',
      algorithm: '',
    };
  }

  const password = ensurePassword();
  const algo = options?.algorithm || 'pq2025';
  const result = await create({ name: 'jacs-agent', password, algorithm: algo });

  return {
    agentId: result.agentId,
    name: 'jacs-agent',
    version: '',
    algorithm: algo,
  };
}

/**
 * Zero-config quickstart (sync variant, blocks event loop).
 */
export function quickstartSync(options?: QuickstartOptions): QuickstartInfo {
  strictMode = resolveStrict(options?.strict);
  const configPath = options?.configPath || './jacs.config.json';

  if (fs.existsSync(configPath)) {
    const info = loadSync(configPath);
    return {
      agentId: info.agentId,
      name: info.name || 'jacs-agent',
      version: '',
      algorithm: '',
    };
  }

  const password = ensurePassword();
  const algo = options?.algorithm || 'pq2025';
  const result = createSync({ name: 'jacs-agent', password, algorithm: algo });

  return {
    agentId: result.agentId,
    name: 'jacs-agent',
    version: '',
    algorithm: algo,
  };
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
  strictMode = resolveStrict(options?.strict);

  const requestedPath = configPath || './jacs.config.json';
  const resolvedConfigPath = path.resolve(requestedPath);

  if (!fs.existsSync(resolvedConfigPath)) {
    throw new Error(
      `Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`
    );
  }

  globalAgent = new JacsAgent();
  await globalAgent.load(resolvedConfigPath);

  agentInfo = extractAgentInfo(resolvedConfigPath);
  return agentInfo;
}

/**
 * Loads an existing agent (sync, blocks event loop).
 */
export function loadSync(configPath?: string, options?: LoadOptions): AgentInfo {
  strictMode = resolveStrict(options?.strict);

  const requestedPath = configPath || './jacs.config.json';
  const resolvedConfigPath = path.resolve(requestedPath);

  if (!fs.existsSync(resolvedConfigPath)) {
    throw new Error(
      `Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`
    );
  }

  globalAgent = new JacsAgent();
  globalAgent.loadSync(resolvedConfigPath);

  agentInfo = extractAgentInfo(resolvedConfigPath);
  return agentInfo;
}

/**
 * Verifies the currently loaded agent's integrity.
 */
export async function verifySelf(): Promise<VerificationResult> {
  const agent = requireAgent();

  try {
    await agent.verifyAgent();
    return {
      valid: true,
      signerId: agentInfo?.agentId || '',
      timestamp: '',
      attachments: [],
      errors: [],
    };
  } catch (e) {
    if (strictMode) {
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
 * Verifies the currently loaded agent's integrity (sync).
 */
export function verifySelfSync(): VerificationResult {
  const agent = requireAgent();

  try {
    agent.verifyAgentSync();
    return {
      valid: true,
      signerId: agentInfo?.agentId || '',
      timestamp: '',
      attachments: [],
      errors: [],
    };
  } catch (e) {
    if (strictMode) {
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
 * Signs arbitrary data as a JACS message.
 */
export async function signMessage(data: any): Promise<SignedDocument> {
  const agent = requireAgent();
  const docContent = {
    jacsType: 'message',
    jacsLevel: 'raw',
    content: data,
  };
  const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, null, null);
  return parseSignedResult(result);
}

/**
 * Signs arbitrary data (sync, blocks event loop).
 */
export function signMessageSync(data: any): SignedDocument {
  const agent = requireAgent();
  const docContent = {
    jacsType: 'message',
    jacsLevel: 'raw',
    content: data,
  };
  const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, null, null);
  return parseSignedResult(result);
}

/**
 * Updates the agent document with new data and re-signs it.
 */
export async function updateAgent(newAgentData: any): Promise<string> {
  const agent = requireAgent();
  const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
  return agent.updateAgent(dataString);
}

/**
 * Updates the agent document (sync, blocks event loop).
 */
export function updateAgentSync(newAgentData: any): string {
  const agent = requireAgent();
  const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
  return agent.updateAgentSync(dataString);
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
  const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
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
  const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
  const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
  return parseSignedResult(result);
}

/**
 * Signs a file with optional content embedding.
 */
export async function signFile(filePath: string, embed: boolean = false): Promise<SignedDocument> {
  const agent = requireAgent();

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const docContent = {
    jacsType: 'file',
    jacsLevel: 'raw',
    filename: path.basename(filePath),
  };

  const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, filePath, embed);
  return parseSignedResult(result);
}

/**
 * Signs a file (sync, blocks event loop).
 */
export function signFileSync(filePath: string, embed: boolean = false): SignedDocument {
  const agent = requireAgent();

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const docContent = {
    jacsType: 'file',
    jacsLevel: 'raw',
    filename: path.basename(filePath),
  };

  const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, filePath, embed);
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
    timestamp: '',
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

  try {
    await agent.verifyDocumentById(documentId);
    return {
      valid: true,
      signerId: '',
      timestamp: '',
      attachments: [],
      errors: [],
    };
  } catch (e) {
    if (strictMode) {
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

/**
 * Verifies a document by its storage ID (sync, blocks event loop).
 */
export function verifyByIdSync(documentId: string): VerificationResult {
  const agent = requireAgent();

  if (!documentId.includes(':')) {
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

  try {
    agent.verifyDocumentByIdSync(documentId);
    return {
      valid: true,
      signerId: '',
      timestamp: '',
      attachments: [],
      errors: [],
    };
  } catch (e) {
    if (strictMode) {
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
    throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
  }
  if (!fs.existsSync(agentInfo.publicKeyPath)) {
    throw new Error(`Public key not found: ${agentInfo.publicKeyPath}`);
  }
  return fs.readFileSync(agentInfo.publicKeyPath, 'utf8');
}

export function exportAgent(): string {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
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
    throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
  }
  const agentDoc = JSON.parse(exportAgent());
  const jacsId = agentDoc.jacsId || agentDoc.agentId || '';
  const publicKeyHash =
    agentDoc.jacsSignature?.publicKeyHash ||
    agentDoc.jacsSignature?.['publicKeyHash'] ||
    '';
  const d = domain.replace(/\.$/, '');
  const owner = `_v1.agent.jacs.${d}.`;
  const txt = `v=hai.ai; jacs_agent_id=${jacsId}; alg=SHA-256; enc=base64; jac_public_key_hash=${publicKeyHash}`;
  return `${owner} ${ttl} IN TXT "${txt}"`;
}

export function getWellKnownJson(): {
  publicKey: string;
  publicKeyHash: string;
  algorithm: string;
  agentId: string;
} {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
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
// HAI Registration
// =============================================================================

export async function registerWithHai(
  options?: HaiRegistrationOptions
): Promise<HaiRegistrationResult> {
  if (!agentInfo) {
    throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
  }
  const apiKey = options?.apiKey ?? process.env.HAI_API_KEY;
  if (!apiKey) {
    throw new Error('HAI registration requires an API key. Set apiKey in options or HAI_API_KEY env.');
  }
  if (options?.preview) {
    return {
      agentId: agentInfo.agentId,
      jacsId: '',
      dnsVerified: false,
      signatures: [],
    };
  }
  const baseUrl = (options?.haiUrl ?? 'https://hai.ai').replace(/\/$/, '');
  const agentJson = exportAgent();
  const url = `${baseUrl}/api/v1/agents/register`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ agent_json: agentJson }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HAI registration failed: ${res.status} ${text}`);
  }
  const data = (await res.json()) as {
    agent_id?: string;
    jacs_id?: string;
    dns_verified?: boolean;
    signatures?: Array<{ key_id?: string; signature?: string }>;
  };
  const signatures = (data.signatures ?? []).map(
    (s) => (typeof s === 'string' ? s : s.signature ?? s.key_id ?? '')
  );
  return {
    agentId: data.agent_id ?? '',
    jacsId: data.jacs_id ?? '',
    dnsVerified: data.dns_verified ?? false,
    signatures,
  };
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
// Verify link
// =============================================================================

export const MAX_VERIFY_URL_LEN = 2048;
export const MAX_VERIFY_DOCUMENT_BYTES = 1515;

export function generateVerifyLink(
  document: string,
  baseUrl: string = 'https://hai.ai',
): string {
  const base = baseUrl.replace(/\/+$/, '');
  const encoded = Buffer.from(document, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  const fullUrl = `${base}/jacs/verify?s=${encoded}`;
  if (fullUrl.length > MAX_VERIFY_URL_LEN) {
    throw new Error(
      `Verify URL would exceed max length (${MAX_VERIFY_URL_LEN}). Document size must be at most ${MAX_VERIFY_DOCUMENT_BYTES} UTF-8 bytes.`,
    );
  }
  return fullUrl;
}
