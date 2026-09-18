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

import { channel as diagnosticsChannel } from 'node:diagnostics_channel';

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
  verifyDocumentStandalone as nativeVerifyDocumentStandalone,
  auditSync as nativeAuditSync,
  audit as nativeAudit,
  quickstartPrivateKeyPassword as nativeQuickstartPrivateKeyPassword,
  resolvePrivateKeyPassword as nativeResolvePrivateKeyPassword,
} from './index';
import * as path from 'path';
import * as fs from 'fs';
import { createHash } from 'crypto';
import { warnDeprecated } from './deprecation';
import {
  authenticatedSignatureMetadata,
  normalizeAgreementStatus,
  normalizeAttestationVerificationResult,
  requireLiteralTrueVerification,
} from './verification';

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
  /** Local enrollment only, not Current/purpose authorization. Missing means unavailable. */
  identityBindingStatus?: 'unavailable' | 'locally_enrolled';
  identityBound?: boolean;
  data?: any;
  signerId: string;
  signerName?: string;
  timestamp: string;
  attachments: Attachment[];
  errors: string[];
}

export type SignedEventReplayErrorCode =
  | 'replay_duplicate'
  | 'replay_store_unavailable'
  | 'replay_store_timeout'
  | 'replay_store_invalid_result'
  | 'replay_store_not_shared'
  | 'signed_event_expired';

export type SignedEventReplayPreparer = JacsAgent | JacsSimpleAgent;

export interface SharedReplayStore {
  readonly scope: 'shared';
  /** Stable operational label; must be a nonblank string. */
  readonly name: string;
  /**
   * Must be declared with `async`, perform nonblocking I/O, and honor the
   * AbortSignal. Synchronous work blocks JavaScript's event loop and therefore
   * cannot be preempted by any Promise-based timeout.
   */
  consume(
    key: string,
    ttlSeconds: number,
    signal: AbortSignal,
  ): Promise<boolean>;
}

export interface SignedEventReplayOptions {
  /** Freshness window passed to native cryptographic verification. Default 300. */
  maxAgeSeconds?: number;
  /** Application replay-store deadline in milliseconds. Default 5000, maximum 30000. */
  timeoutMs?: number;
}

export interface SignedEventReplayPreparation {
  contractVersion: 1;
  status: 'crypto_verified_replay_pending';
  cryptographicallyVerified: true;
  freshnessVerified: true;
  replayConsumed: false;
  signerId: string;
  timestamp: string;
  algorithm: string;
  documentId: string;
  eventSha256: string;
  replayKey: string;
  replayTtlSeconds: number;
  expiresAtUnixSeconds: number;
}

export interface VerifiedSignedEvent<T = unknown> {
  status: 'verified';
  verified: true;
  replayConsumed: true;
  data: T;
  signerId: string;
  timestamp: string;
  algorithm: string;
  documentId: string;
}

export interface SignedEventReplaySecurityEvent {
  level: 'warn';
  event: 'jacs_security_outcome';
  operation: 'signed_event_replay';
  outcome: 'rejected';
  error_code: SignedEventReplayErrorCode;
}

/** Node diagnostics_channel name for structured JACS security outcomes. */
export const JACS_SECURITY_DIAGNOSTICS_CHANNEL = 'jacs.security';
const jacsSecurityChannel = diagnosticsChannel(JACS_SECURITY_DIAGNOSTICS_CHANNEL);

export class SignedEventReplayError extends Error {
  readonly code: SignedEventReplayErrorCode;

  constructor(code: SignedEventReplayErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'SignedEventReplayError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
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
/**
 * Auxiliary global JacsSimpleAgent used by the inline-text / image
 * module-level helpers (signText / verifyText / signImage / verifyImage /
 * extractMediaSignature). See JacsClient for the same pattern.
 */
let globalSimpleAgent: JacsSimpleAgent | null = null;
let agentInfo: AgentInfo | null = null;
let strictMode: boolean = false;

function adoptClientState(client: unknown): AgentInfo {
  const state = client as {
    agent: JacsAgent | null;
    simpleAgent: JacsSimpleAgent | null;
    info: AgentInfo | null;
    _strict: boolean;
  };
  globalAgent = state.agent ?? null;
  globalSimpleAgent = state.simpleAgent ?? null;
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

const DEFAULT_SIGNED_EVENT_MAX_AGE_SECONDS = 300;
const DEFAULT_REPLAY_STORE_TIMEOUT_MS = 5_000;
const MAX_REPLAY_STORE_TIMEOUT_MS = 30_000;
const MAX_NAPI_U32 = 0xffff_ffff;
const MAX_SIGNED_EVENT_FUTURE_SKEW_SECONDS = 300;
const SIGNED_EVENT_REPLAY_PREPARATION_FIELDS = Object.freeze([
  'contractVersion',
  'status',
  'cryptographicallyVerified',
  'freshnessVerified',
  'replayConsumed',
  'signerId',
  'timestamp',
  'algorithm',
  'documentId',
  'eventSha256',
  'replayKey',
  'replayTtlSeconds',
  'expiresAtUnixSeconds',
] as const);
const SIGNED_EVENT_REPLAY_PREPARATION_FIELD_SET = new Set<string>(
  SIGNED_EVENT_REPLAY_PREPARATION_FIELDS,
);
const NATIVE_JACS_AGENT_DIAGNOSTICS = JacsAgent.prototype.diagnostics;
const NATIVE_JACS_SIMPLE_AGENT_DIAGNOSTICS = JacsSimpleAgent.prototype.diagnostics;

function replayFailure(
  code: SignedEventReplayErrorCode,
  message: string,
): SignedEventReplayError {
  return new SignedEventReplayError(code, message);
}

function publishReplayRejection(error: SignedEventReplayError): void {
  const event: SignedEventReplaySecurityEvent = {
    level: 'warn',
    event: 'jacs_security_outcome',
    operation: 'signed_event_replay',
    outcome: 'rejected',
    error_code: error.code,
  };
  jacsSecurityChannel.publish(event);
}

function hasOwn(value: object, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, field);
}

function requirePositiveSafeInteger(
  value: number,
  name: string,
  maximum: number = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw replayFailure(
      'replay_store_invalid_result',
      `${name} must be a positive safe integer no greater than ${maximum}`,
    );
  }
  return value;
}

function isWellFormedUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return false;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function requireWellFormedUtf16(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !isWellFormedUtf16(value)) {
    throw replayFailure(
      'replay_store_invalid_result',
      `${name} must be a well-formed UTF-16 string`,
    );
  }
}

function advanceJsonString(raw: string, start: number): number {
  let index = start + 1;
  while (index < raw.length) {
    const codeUnit = raw.charCodeAt(index);
    if (codeUnit === 0x22) {
      return index + 1;
    }
    if (codeUnit === 0x5c) {
      index += 2;
      continue;
    }
    index += 1;
  }
  return raw.length;
}

function skipJsonWhitespace(raw: string, start: number): number {
  let index = start;
  while (index < raw.length && /\s/.test(raw[index])) {
    index += 1;
  }
  return index;
}

// JSON.parse overwrites duplicate object names. Native preparation is a flat
// object, so scan its top-level names as written before trusting the parsed
// value. Decoding each name also catches escaped aliases such as st\u0061tus.
function topLevelJsonObjectKeys(raw: string): string[] {
  const keys: string[] = [];
  const seen = new Set<string>();
  let index = skipJsonWhitespace(raw, 0);
  if (raw[index] !== '{') {
    return keys;
  }
  index += 1;

  while (index < raw.length) {
    index = skipJsonWhitespace(raw, index);
    if (raw[index] === '}') {
      return keys;
    }
    if (raw[index] !== '"') {
      return keys;
    }
    const keyStart = index;
    index = advanceJsonString(raw, index);
    const key = JSON.parse(raw.slice(keyStart, index)) as string;
    if (seen.has(key)) {
      throw replayFailure(
        'replay_store_invalid_result',
        `native replay preparation contains duplicate field ${key}`,
      );
    }
    seen.add(key);
    keys.push(key);

    index = skipJsonWhitespace(raw, index);
    if (raw[index] !== ':') {
      return keys;
    }
    index = skipJsonWhitespace(raw, index + 1);

    let nesting = 0;
    while (index < raw.length) {
      const character = raw[index];
      if (character === '"') {
        index = advanceJsonString(raw, index);
        continue;
      }
      if (character === '{' || character === '[') {
        nesting += 1;
      } else if (character === '}' || character === ']') {
        if (nesting === 0) {
          break;
        }
        nesting -= 1;
      } else if (character === ',' && nesting === 0) {
        break;
      }
      index += 1;
    }

    if (raw[index] === ',') {
      index += 1;
      continue;
    }
    return keys;
  }
  return keys;
}

function daysInUtcMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function parseStrictRfc3339UnixSeconds(value: string): number {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation timestamp must be strict RFC 3339',
    );
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] === 'Z' ? 0 : Number(match[10]);
  const offsetMinute = match[8] === 'Z' ? 0 : Number(match[11]);
  if (
    year < 1970
    || month < 1 || month > 12
    || day < 1 || day > daysInUtcMonth(year, month)
    || hour > 23 || minute > 59 || second > 59
    || offsetHour > 23 || offsetMinute > 59
  ) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation timestamp is not a valid RFC 3339 instant',
    );
  }

  const instant = new Date(0);
  instant.setUTCFullYear(year, month - 1, day);
  instant.setUTCHours(hour, minute, second, 0);
  let unixSeconds = Math.floor(instant.getTime() / 1000);
  if (match[8] !== 'Z') {
    const offsetSeconds = offsetHour * 3600 + offsetMinute * 60;
    unixSeconds += match[9] === '+' ? -offsetSeconds : offsetSeconds;
  }
  if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation timestamp is outside the supported range',
    );
  }
  return unixSeconds;
}

function isNativeReplayAgent(agent: unknown): agent is SignedEventReplayPreparer {
  try {
    if (agent instanceof JacsAgent) {
      NATIVE_JACS_AGENT_DIAGNOSTICS.call(agent);
      return true;
    }
    if (agent instanceof JacsSimpleAgent) {
      NATIVE_JACS_SIMPLE_AGENT_DIAGNOSTICS.call(agent);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function isAsyncFunction(value: Function): boolean {
  try {
    const source = Function.prototype.toString.call(value);
    return Object.prototype.toString.call(value) === '[object AsyncFunction]'
      && /^\s*async(?:\s+function\b|\s*\(|\s+[A-Za-z_$])/.test(source);
  } catch {
    return false;
  }
}

interface ValidatedSharedReplayStore {
  receiver: SharedReplayStore;
  consume: SharedReplayStore['consume'];
}

function validateSharedReplayStore(store: unknown): ValidatedSharedReplayStore {
  if (!store || (typeof store !== 'object' && typeof store !== 'function')) {
    throw replayFailure(
      'replay_store_not_shared',
      'signed-event delivery requires a shared replay store',
    );
  }

  let scope: unknown;
  let name: unknown;
  let consume: unknown;
  try {
    const runtimeStore = store as Record<string, unknown>;
    scope = runtimeStore.scope;
    name = runtimeStore.name;
    consume = runtimeStore.consume;
  } catch {
    throw replayFailure(
      'replay_store_unavailable',
      'shared replay store metadata could not be read',
    );
  }
  if (scope !== 'shared') {
    throw replayFailure(
      'replay_store_not_shared',
      'signed-event delivery requires store.scope === "shared"',
    );
  }
  if (typeof name !== 'string' || name.trim().length === 0) {
    throw replayFailure(
      'replay_store_invalid_result',
      'shared replay store must provide a nonblank string name',
    );
  }
  if (typeof consume !== 'function') {
    throw replayFailure(
      'replay_store_unavailable',
      'shared replay store must provide consume(key, ttlSeconds, signal)',
    );
  }
  if (!isAsyncFunction(consume)) {
    throw replayFailure(
      'replay_store_invalid_result',
      'shared replay store consume must be declared async',
    );
  }
  return {
    receiver: store as SharedReplayStore,
    consume: consume as SharedReplayStore['consume'],
  };
}

function parseReplayPreparation(
  rawPreparation: string,
  immutableEventJson: string,
  maxAgeSeconds: number,
): SignedEventReplayPreparation {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawPreparation);
  } catch {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation was not valid JSON',
    );
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation must be a JSON object',
    );
  }
  const preparation = parsed as Record<string, unknown>;

  const rawFields = topLevelJsonObjectKeys(rawPreparation);
  const parsedFields = Object.keys(preparation);
  if (
    rawFields.length !== SIGNED_EVENT_REPLAY_PREPARATION_FIELDS.length
    || parsedFields.length !== SIGNED_EVENT_REPLAY_PREPARATION_FIELDS.length
    || rawFields.some((field) => !SIGNED_EVENT_REPLAY_PREPARATION_FIELD_SET.has(field))
    || parsedFields.some((field) => !SIGNED_EVENT_REPLAY_PREPARATION_FIELD_SET.has(field))
  ) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation fields do not exactly match contract version 1',
    );
  }

  if (
    preparation.contractVersion !== 1
    || preparation.status !== 'crypto_verified_replay_pending'
    || preparation.cryptographicallyVerified !== true
    || preparation.freshnessVerified !== true
    || preparation.replayConsumed !== false
  ) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation did not satisfy the fixed contract values',
    );
  }

  for (const field of [
    'signerId',
    'timestamp',
    'algorithm',
    'documentId',
    'eventSha256',
    'replayKey',
  ]) {
    const value = preparation[field];
    if (typeof value !== 'string' || value.length === 0 || !isWellFormedUtf16(value)) {
      throw replayFailure(
        'replay_store_invalid_result',
        `native replay preparation field ${field} must be a non-empty well-formed string`,
      );
    }
  }

  const expectedSha256 = createHash('sha256')
    .update(immutableEventJson, 'utf8')
    .digest('hex');
  if (
    !/^[0-9a-f]{64}$/.test(preparation.eventSha256 as string)
    || preparation.eventSha256 !== expectedSha256
  ) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation did not bind the exact signed-event UTF-8 bytes',
    );
  }
  const signerId = preparation.signerId as string;
  const documentId = preparation.documentId as string;
  const replayScope = `signed-event:${signerId}`;
  const expectedReplayKey = `jacs-replay-v1:${Buffer.byteLength(replayScope, 'utf8')}:${replayScope}:${documentId}`;
  if (preparation.replayKey !== expectedReplayKey) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation replay key does not match signer and document',
    );
  }

  const maximumReplayTtlSeconds = maxAgeSeconds + MAX_SIGNED_EVENT_FUTURE_SKEW_SECONDS + 1;
  const replayTtlSeconds = requirePositiveSafeInteger(
    preparation.replayTtlSeconds as number,
    'replayTtlSeconds',
    maximumReplayTtlSeconds,
  );
  const expiresAtUnixSeconds = requirePositiveSafeInteger(
    preparation.expiresAtUnixSeconds as number,
    'expiresAtUnixSeconds',
  );
  const issuedAtUnixSeconds = parseStrictRfc3339UnixSeconds(preparation.timestamp as string);
  const nowUnixSeconds = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < 0) {
    throw replayFailure(
      'replay_store_invalid_result',
      'system clock is outside the supported range',
    );
  }
  if (issuedAtUnixSeconds > nowUnixSeconds + MAX_SIGNED_EVENT_FUTURE_SKEW_SECONDS) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation timestamp exceeds allowed future skew',
    );
  }
  const expectedExpiry = issuedAtUnixSeconds + maxAgeSeconds;
  if (!Number.isSafeInteger(expectedExpiry) || expectedExpiry !== expiresAtUnixSeconds) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation expiry does not match timestamp plus maxAgeSeconds',
    );
  }

  if (nowUnixSeconds > expiresAtUnixSeconds) {
    throw replayFailure('signed_event_expired', 'signed event expired before replay consumption');
  }
  const minimumSafeTtl = expiresAtUnixSeconds - nowUnixSeconds + 1;
  if (replayTtlSeconds < minimumSafeTtl) {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay TTL ends before the signed event absolute expiry',
    );
  }

  return preparation as unknown as SignedEventReplayPreparation;
}

async function consumeReplayWithTimeout(
  store: ValidatedSharedReplayStore,
  replayKey: string,
  replayTtlSeconds: number,
  timeoutMs: number,
): Promise<unknown> {
  const controller = new AbortController();
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutError = replayFailure(
    'replay_store_timeout',
    `shared replay store did not respond within ${timeoutMs}ms`,
  );
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      reject(timeoutError);
    }, timeoutMs);
  });
  const consumption = Promise.resolve().then(() =>
    store.consume.call(store.receiver, replayKey, replayTtlSeconds, controller.signal));

  try {
    return await Promise.race([consumption, timeout]);
  } catch (error) {
    if (timedOut || error === timeoutError) {
      throw timeoutError;
    }
    throw replayFailure(
      'replay_store_unavailable',
      'shared replay store consume failed',
    );
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
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
  return {
    agentId: info.agent_id || '',
    name: info.name || options.name,
    publicKeyPath: info.public_key_path || '',
    configPath,
    version: info.version || '',
    algorithm: info.algorithm || options.algorithm || 'pq2025',
    privateKeyPath: info.private_key_path || '',
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
  const signatureMetadata = authenticatedSignatureMetadata(doc);

  const makeSuccess = (): VerificationResult => ({
    valid: true,
    data: doc.content,
    signerId: signatureMetadata.signerId,
    timestamp: signatureMetadata.timestamp,
    attachments: extractAttachments(),
    errors: [],
  });

  const makeFailure = (e: any): VerificationResult => {
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
  };

  if (isSync) {
    try {
      const verified = agent.verifyDocumentSync(signedDocument);
      requireLiteralTrueVerification(verified, 'Native document verification');
      return makeSuccess();
    } catch (e) {
      return makeFailure(e);
    }
  } else {
    return agent.verifyDocument(signedDocument)
      .then((verified) => {
        requireLiteralTrueVerification(verified, 'Native document verification');
        return makeSuccess();
      })
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

function ensurePassword(configPath?: string | null, keyDirectory?: string | null): string {
  return nativeQuickstartPrivateKeyPassword(
    configPath ? path.resolve(configPath) : null,
    keyDirectory ?? null,
  );
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
  const p = resolvePrivateKeyPassword(
    options.configPath ?? null,
    options.keyDirectory ?? null,
    options.password ?? null,
  );
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
    const verified = await agent.verifyAgent();
    requireLiteralTrueVerification(verified, 'Native agent verification');
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
    const verified = agent.verifyAgentSync();
    requireLiteralTrueVerification(verified, 'Native agent verification');
    return makeVerificationSuccess(agentInfo?.agentId || '');
  } catch (e) {
    return makeVerificationFailure(e, 'Self-verification failed');
  }
}

/**
 * Signs arbitrary data with the legacy signed-message type label.
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
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

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
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const docContent = createRawDocumentPayload('file', {
    filename: path.basename(filePath),
  });
  return withAgentPasswordSync((agent) => {
    const result = createDocumentImpl(agent, docContent, filePath, embed, true) as string;
    return parseSignedResult(result);
  });
}

// =============================================================================
// Inline text + image (Task 11 — PRD §3.1, §3.2, §4.1, §4.2)
// =============================================================================
//
// These module-level helpers route through the auxiliary `globalSimpleAgent`
// adopted by `adoptClientState`. They mirror the corresponding `JacsClient`
// methods (see `client.ts`).

export interface SignTextOpts {
  noBackup?: boolean;
}

export interface VerifyTextOpts {
  /** C1: missing-signature throws when true. Default false. */
  strict?: boolean;
  /** PRD §4.1.5. */
  keyDir?: string;
}

export interface SignImageOpts {
  /** PRD §4.2.4 LSB embedding. Default false (Q4). */
  robust?: boolean;
  format?: string;
  /** PRD §4.2.2 single-signer guard. */
  refuseOverwrite?: boolean;
}

export interface VerifyImageOpts {
  strict?: boolean;
  keyDir?: string;
  /** PRD §4.2.4 LSB scan fallback. */
  robust?: boolean;
}

export interface ExtractMediaOpts {
  /** PRD §3.2 wire form. */
  rawPayload?: boolean;
}

function requireSimpleAgent(): JacsSimpleAgent {
  if (!globalSimpleAgent) {
    throw new Error(
      'No agent loaded. Call quickstart({ name, domain }), load(), or create() first.',
    );
  }
  return globalSimpleAgent;
}

/**
 * Named roles accepted by {@link signAgreementV2}. The methods still accept the
 * raw lowercase strings; these symbols document the allowed values.
 */
export type AgreementV2Role = 'signer' | 'witness' | 'notary';

/** Constant accessor for the {@link AgreementV2Role} values. */
export const AgreementV2Role = {
  SIGNER: 'signer',
  WITNESS: 'witness',
  NOTARY: 'notary',
} as const;

/**
 * Shape of the JSON object returned (as a string, or parsed for the `verify*`
 * variants) by {@link verifyAgreementV2}. Field names are camelCase to match
 * the wire format emitted by the Rust verifier.
 */
export interface AgreementV2VerificationReport {
  /** Always false: consent-signature inspection is not policy acceptance. */
  valid: boolean;
  /** Mathematical and structural checks only; not authorization. */
  mathematicalChecksValid: boolean;
  policyAccepted: false;
  overallScope: 'consent_signatures_only';
  status: string;
  expectedStatus: string;
  recomputedAgreementHash: string;
  recomputedTranscriptHash: string;
  signerCount: number;
  witnessCount: number;
  notaryCount: number;
  verifiedChainDepth?: number;
  chainFullyVerified?: boolean;
  errors?: string[];
  notes?: string[];
}

/**
 * Shape of the branch/merge analysis returned by
 * {@link detectAgreementV2BranchConflict}.
 */
export interface AgreementV2MergeAnalysis {
  sameDocument: boolean;
  sameParent: boolean;
  autoMergeable: boolean;
  conflictFields?: string[];
  leftChangedFields?: string[];
  rightChangedFields?: string[];
  leftTranscriptAdditions: number;
  rightTranscriptAdditions: number;
  errors?: string[];
}

export async function createAgreementV2(input: any): Promise<string> {
  return requireSimpleAgent().createAgreementV2(normalizeJsonInput(input));
}

export function createAgreementV2Sync(input: any): string {
  return requireSimpleAgent().createAgreementV2Sync(normalizeJsonInput(input));
}

export async function applyAgreementV2(document: any, mutation: any): Promise<string> {
  return requireSimpleAgent().applyAgreementV2(
    normalizeDocumentInput(document),
    normalizeJsonInput(mutation),
  );
}

export function applyAgreementV2Sync(document: any, mutation: any): string {
  return requireSimpleAgent().applyAgreementV2Sync(
    normalizeDocumentInput(document),
    normalizeJsonInput(mutation),
  );
}

export async function signAgreementV2(document: any, role: string = 'signer'): Promise<string> {
  return requireSimpleAgent().signAgreementV2(normalizeDocumentInput(document), role);
}

export function signAgreementV2Sync(document: any, role: string = 'signer'): string {
  return requireSimpleAgent().signAgreementV2Sync(normalizeDocumentInput(document), role);
}

export async function verifyAgreementV2(document: any): Promise<any> {
  return requireSimpleAgent().verifyAgreementV2(normalizeDocumentInput(document));
}

export function verifyAgreementV2Sync(document: any): any {
  return requireSimpleAgent().verifyAgreementV2Sync(normalizeDocumentInput(document));
}

/**
 * Convenience wrapper over {@link verifyAgreementV2} that types the parsed
 * report. Identical runtime behaviour; only the static type is narrowed.
 */
export async function verifyAgreementV2Typed(
  document: any,
): Promise<AgreementV2VerificationReport> {
  return (await verifyAgreementV2(document)) as AgreementV2VerificationReport;
}

/** Sync variant of {@link verifyAgreementV2Typed}. */
export function verifyAgreementV2TypedSync(
  document: any,
): AgreementV2VerificationReport {
  return verifyAgreementV2Sync(document) as AgreementV2VerificationReport;
}

export async function detectAgreementV2BranchConflict(base: any, left: any, right: any): Promise<any> {
  return requireSimpleAgent().detectAgreementV2BranchConflict(
    normalizeDocumentInput(base),
    normalizeDocumentInput(left),
    normalizeDocumentInput(right),
  );
}

export function detectAgreementV2BranchConflictSync(base: any, left: any, right: any): any {
  return requireSimpleAgent().detectAgreementV2BranchConflictSync(
    normalizeDocumentInput(base),
    normalizeDocumentInput(left),
    normalizeDocumentInput(right),
  );
}

/**
 * Convenience wrapper over {@link detectAgreementV2BranchConflict} that types
 * the parsed analysis. Identical runtime behaviour.
 */
export async function detectAgreementV2BranchConflictTyped(
  base: any,
  left: any,
  right: any,
): Promise<AgreementV2MergeAnalysis> {
  return (await detectAgreementV2BranchConflict(
    base,
    left,
    right,
  )) as AgreementV2MergeAnalysis;
}

/** Sync variant of {@link detectAgreementV2BranchConflictTyped}. */
export function detectAgreementV2BranchConflictTypedSync(
  base: any,
  left: any,
  right: any,
): AgreementV2MergeAnalysis {
  return detectAgreementV2BranchConflictSync(
    base,
    left,
    right,
  ) as AgreementV2MergeAnalysis;
}

export async function mergeAgreementV2TranscriptBranches(base: any, left: any, right: any): Promise<string> {
  return requireSimpleAgent().mergeAgreementV2TranscriptBranches(
    normalizeDocumentInput(base),
    normalizeDocumentInput(left),
    normalizeDocumentInput(right),
  );
}

export function mergeAgreementV2TranscriptBranchesSync(base: any, left: any, right: any): string {
  return requireSimpleAgent().mergeAgreementV2TranscriptBranchesSync(
    normalizeDocumentInput(base),
    normalizeDocumentInput(left),
    normalizeDocumentInput(right),
  );
}

export async function resolveAgreementV2BranchConflict(base: any, previous: any, side: any, mutation: any): Promise<string> {
  return requireSimpleAgent().resolveAgreementV2BranchConflict(
    normalizeDocumentInput(base),
    normalizeDocumentInput(previous),
    normalizeDocumentInput(side),
    normalizeJsonInput(mutation),
  );
}

export function resolveAgreementV2BranchConflictSync(base: any, previous: any, side: any, mutation: any): string {
  return requireSimpleAgent().resolveAgreementV2BranchConflictSync(
    normalizeDocumentInput(base),
    normalizeDocumentInput(previous),
    normalizeDocumentInput(side),
    normalizeJsonInput(mutation),
  );
}

export async function signText(filePath: string, opts?: SignTextOpts): Promise<any> {
  return requireSimpleAgent().signText(filePath, opts?.noBackup ?? false);
}

export function signTextSync(filePath: string, opts?: SignTextOpts): any {
  return requireSimpleAgent().signTextSync(filePath, opts?.noBackup ?? false);
}

export async function verifyText(filePath: string, opts?: VerifyTextOpts): Promise<any> {
  return requireSimpleAgent().verifyText(filePath, {
    strict: opts?.strict ?? false,
    keyDir: opts?.keyDir,
  });
}

export function verifyTextSync(filePath: string, opts?: VerifyTextOpts): any {
  return requireSimpleAgent().verifyTextSync(filePath, {
    strict: opts?.strict ?? false,
    keyDir: opts?.keyDir,
  });
}

export async function signImage(
  inputPath: string,
  outputPath: string,
  opts?: SignImageOpts,
): Promise<any> {
  return requireSimpleAgent().signImage(inputPath, outputPath, {
    robust: opts?.robust ?? false,
    format: opts?.format,
    refuseOverwrite: opts?.refuseOverwrite ?? false,
  });
}

export function signImageSync(
  inputPath: string,
  outputPath: string,
  opts?: SignImageOpts,
): any {
  return requireSimpleAgent().signImageSync(inputPath, outputPath, {
    robust: opts?.robust ?? false,
    format: opts?.format,
    refuseOverwrite: opts?.refuseOverwrite ?? false,
  });
}

export async function verifyImage(filePath: string, opts?: VerifyImageOpts): Promise<any> {
  return requireSimpleAgent().verifyImage(filePath, {
    strict: opts?.strict ?? false,
    keyDir: opts?.keyDir,
    robust: opts?.robust ?? false,
  });
}

export function verifyImageSync(filePath: string, opts?: VerifyImageOpts): any {
  return requireSimpleAgent().verifyImageSync(filePath, {
    strict: opts?.strict ?? false,
    keyDir: opts?.keyDir,
    robust: opts?.robust ?? false,
  });
}

export async function extractMediaSignature(
  filePath: string,
  opts?: ExtractMediaOpts,
): Promise<string | null> {
  return requireSimpleAgent().extractMediaSignature(filePath, {
    rawPayload: opts?.rawPayload ?? false,
  });
}

export function extractMediaSignatureSync(
  filePath: string,
  opts?: ExtractMediaOpts,
): string | null {
  return requireSimpleAgent().extractMediaSignatureSync(filePath, {
    rawPayload: opts?.rawPayload ?? false,
  });
}

/**
 * Verify an exact signed-event JSON string, atomically consume its replay key
 * in an application-owned shared store, and only then release its data.
 *
 * The native preparation step runs on the NAPI worker pool. The application
 * store must implement a cross-replica atomic consume operation where literal
 * `true` means this was the first accepted delivery and literal `false` means
 * a duplicate.
 */
async function unwrapSignedEventWithReplayStoreImpl<T = unknown>(
  agent: SignedEventReplayPreparer,
  eventJson: string,
  serverKeysJson: string,
  store: SharedReplayStore,
  options: SignedEventReplayOptions = {},
): Promise<VerifiedSignedEvent<T>> {
  requireWellFormedUtf16(eventJson, 'eventJson');
  requireWellFormedUtf16(serverKeysJson, 'serverKeysJson');
  if (!isNativeReplayAgent(agent)) {
    throw replayFailure(
      'replay_store_invalid_result',
      'agent must be a native JacsAgent or JacsSimpleAgent instance',
    );
  }
  const validatedStore = validateSharedReplayStore(store);

  const maxAgeSeconds = requirePositiveSafeInteger(
    options.maxAgeSeconds ?? DEFAULT_SIGNED_EVENT_MAX_AGE_SECONDS,
    'maxAgeSeconds',
    MAX_NAPI_U32,
  );
  const requestedTimeoutMs = requirePositiveSafeInteger(
    options.timeoutMs ?? DEFAULT_REPLAY_STORE_TIMEOUT_MS,
    'timeoutMs',
  );
  const timeoutMs = Math.min(requestedTimeoutMs, MAX_REPLAY_STORE_TIMEOUT_MS);
  const immutableEventJson = eventJson;

  // Do not parse the event or inspect its data before native cryptographic and
  // freshness verification produces a no-payload preparation claim.
  const rawPreparation = await agent.prepareSignedEventReplay(
    immutableEventJson,
    serverKeysJson,
    maxAgeSeconds,
  );
  if (typeof rawPreparation !== 'string') {
    throw replayFailure(
      'replay_store_invalid_result',
      'native replay preparation must be returned as a JSON string',
    );
  }
  const preparation = parseReplayPreparation(
    rawPreparation,
    immutableEventJson,
    maxAgeSeconds,
  );

  const consumed = await consumeReplayWithTimeout(
    validatedStore,
    preparation.replayKey,
    preparation.replayTtlSeconds,
    timeoutMs,
  );
  if (consumed === false) {
    throw replayFailure('replay_duplicate', 'signed event replay key was already consumed');
  }
  if (consumed !== true) {
    throw replayFailure(
      'replay_store_invalid_result',
      'shared replay store consume must return literal true or false',
    );
  }
  if (Math.floor(Date.now() / 1000) > preparation.expiresAtUnixSeconds) {
    throw replayFailure('signed_event_expired', 'signed event expired during replay consumption');
  }

  // The string passed to native verification is immutable. Parse that same
  // value only after atomic replay consumption succeeds.
  let event: unknown;
  try {
    event = JSON.parse(immutableEventJson);
  } catch {
    throw replayFailure(
      'replay_store_invalid_result',
      'verified signed-event JSON could not be parsed after replay consumption',
    );
  }
  if (!event || typeof event !== 'object' || Array.isArray(event) || !hasOwn(event, 'data')) {
    throw replayFailure(
      'replay_store_invalid_result',
      'verified signed event did not contain data',
    );
  }

  return {
    status: 'verified',
    verified: true,
    replayConsumed: true,
    data: (event as Record<string, unknown>).data as T,
    signerId: preparation.signerId,
    timestamp: preparation.timestamp,
    algorithm: preparation.algorithm,
    documentId: preparation.documentId,
  };
}

export async function unwrapSignedEventWithReplayStore<T = unknown>(
  agent: SignedEventReplayPreparer,
  eventJson: string,
  serverKeysJson: string,
  store: SharedReplayStore,
  options: SignedEventReplayOptions = {},
): Promise<VerifiedSignedEvent<T>> {
  try {
    return await unwrapSignedEventWithReplayStoreImpl<T>(
      agent,
      eventJson,
      serverKeysJson,
      store,
      options,
    );
  } catch (error) {
    if (error instanceof SignedEventReplayError) {
      publishReplayRejection(error);
    }
    throw error;
  }
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
  const valid = r?.valid === true;
  return {
    valid,
    identityBindingStatus: valid && r.identityBindingStatus === 'locally_enrolled' ? 'locally_enrolled' : 'unavailable',
    identityBound: valid && r.identityBindingStatus === 'locally_enrolled',
    signerId: valid && typeof r.signerId === 'string' ? r.signerId : '',
    timestamp: valid && typeof r.timestamp === 'string' ? r.timestamp : '',
    attachments: [],
    errors: valid ? [] : ['Native standalone verification did not return literal true'],
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
    const verified = await agent.verifyDocumentById(documentId);
    requireLiteralTrueVerification(verified, 'Native stored-document verification');
    const storedJson = await agent.getDocumentById(documentId);
    const stored = JSON.parse(storedJson);
    const metadata = authenticatedSignatureMetadata(stored);
    return {
      ...makeVerificationSuccess(metadata.signerId),
      timestamp: metadata.timestamp,
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
    const verified = agent.verifyDocumentByIdSync(documentId);
    requireLiteralTrueVerification(verified, 'Native stored-document verification');
    const storedJson = agent.getDocumentByIdSync(documentId);
    const stored = JSON.parse(storedJson);
    const metadata = authenticatedSignatureMetadata(stored);
    return {
      ...makeVerificationSuccess(metadata.signerId),
      timestamp: metadata.timestamp,
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
// Format Conversion (YAML / HTML)
// =============================================================================

/**
 * Convert a JSON string to YAML (async).
 */
export async function toYaml(jsonStr: string): Promise<string> {
  return requireAgent().toYaml(jsonStr);
}

/**
 * Convert a JSON string to YAML (sync).
 */
export function toYamlSync(jsonStr: string): string {
  return requireAgent().toYamlSync(jsonStr);
}

/**
 * Convert a YAML string to pretty-printed JSON (async).
 */
export async function fromYaml(yamlStr: string): Promise<string> {
  return requireAgent().fromYaml(yamlStr);
}

/**
 * Convert a YAML string to pretty-printed JSON (sync).
 */
export function fromYamlSync(yamlStr: string): string {
  return requireAgent().fromYamlSync(yamlStr);
}

/**
 * Convert a JSON string to a self-contained HTML document (async).
 */
export async function toHtml(jsonStr: string): Promise<string> {
  return requireAgent().toHtml(jsonStr);
}

/**
 * Convert a JSON string to a self-contained HTML document (sync).
 */
export function toHtmlSync(jsonStr: string): string {
  return requireAgent().toHtmlSync(jsonStr);
}

/**
 * Extract JSON from an HTML document produced by toHtml() (async).
 */
export async function fromHtml(htmlStr: string): Promise<string> {
  return requireAgent().fromHtml(htmlStr);
}

/**
 * Extract JSON from an HTML document produced by toHtml() (sync).
 */
export function fromHtmlSync(htmlStr: string): string {
  return requireAgent().fromHtmlSync(htmlStr);
}

/**
 * Convert YAML to JSON and verify the resulting document (async).
 */
export async function verifyYaml(yamlStr: string): Promise<boolean> {
  return requireAgent().verifyYaml(yamlStr);
}

/**
 * Convert YAML to JSON and verify the resulting document (sync).
 */
export function verifyYamlSync(yamlStr: string): boolean {
  return requireAgent().verifyYamlSync(yamlStr);
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
  return normalizeAgreementStatus(JSON.parse(result));
}

export function checkAgreementSync(
  document: any,
  fieldName?: string
): AgreementStatus {
  const agent = requireAgent();
  const docString = normalizeDocumentInput(document);
  const result = agent.checkAgreementSync(docString, fieldName || null);
  return normalizeAgreementStatus(JSON.parse(result));
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
  return normalizeAttestationVerificationResult(
    JSON.parse(resultJson),
  ) as unknown as AttestationVerificationResult;
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
  return normalizeAttestationVerificationResult(
    JSON.parse(resultJson),
  ) as unknown as AttestationVerificationResult;
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
