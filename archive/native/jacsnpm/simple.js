"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgreementV2Role = exports.SignedEventReplayError = exports.JACS_SECURITY_DIAGNOSTICS_CHANNEL = exports.createConfig = exports.hashString = exports.JacsAgent = void 0;
exports.isStrict = isStrict;
exports.quickstart = quickstart;
exports.quickstartSync = quickstartSync;
exports.create = create;
exports.createSync = createSync;
exports.load = load;
exports.loadSync = loadSync;
exports.verifySelf = verifySelf;
exports.verifySelfSync = verifySelfSync;
exports.signMessage = signMessage;
exports.signMessageSync = signMessageSync;
exports.updateAgent = updateAgent;
exports.updateAgentSync = updateAgentSync;
exports.updateDocument = updateDocument;
exports.updateDocumentSync = updateDocumentSync;
exports.signFile = signFile;
exports.signFileSync = signFileSync;
exports.createAgreementV2 = createAgreementV2;
exports.createAgreementV2Sync = createAgreementV2Sync;
exports.applyAgreementV2 = applyAgreementV2;
exports.applyAgreementV2Sync = applyAgreementV2Sync;
exports.signAgreementV2 = signAgreementV2;
exports.signAgreementV2Sync = signAgreementV2Sync;
exports.verifyAgreementV2 = verifyAgreementV2;
exports.verifyAgreementV2Sync = verifyAgreementV2Sync;
exports.verifyAgreementV2Typed = verifyAgreementV2Typed;
exports.verifyAgreementV2TypedSync = verifyAgreementV2TypedSync;
exports.detectAgreementV2BranchConflict = detectAgreementV2BranchConflict;
exports.detectAgreementV2BranchConflictSync = detectAgreementV2BranchConflictSync;
exports.detectAgreementV2BranchConflictTyped = detectAgreementV2BranchConflictTyped;
exports.detectAgreementV2BranchConflictTypedSync = detectAgreementV2BranchConflictTypedSync;
exports.mergeAgreementV2TranscriptBranches = mergeAgreementV2TranscriptBranches;
exports.mergeAgreementV2TranscriptBranchesSync = mergeAgreementV2TranscriptBranchesSync;
exports.resolveAgreementV2BranchConflict = resolveAgreementV2BranchConflict;
exports.resolveAgreementV2BranchConflictSync = resolveAgreementV2BranchConflictSync;
exports.signText = signText;
exports.signTextSync = signTextSync;
exports.verifyText = verifyText;
exports.verifyTextSync = verifyTextSync;
exports.signImage = signImage;
exports.signImageSync = signImageSync;
exports.verifyImage = verifyImage;
exports.verifyImageSync = verifyImageSync;
exports.extractMediaSignature = extractMediaSignature;
exports.extractMediaSignatureSync = extractMediaSignatureSync;
exports.unwrapSignedEventWithReplayStore = unwrapSignedEventWithReplayStore;
exports.verify = verify;
exports.verifySync = verifySync;
exports.verifyStandalone = verifyStandalone;
exports.verifyById = verifyById;
exports.verifyByIdSync = verifyByIdSync;
exports.reencryptKey = reencryptKey;
exports.reencryptKeySync = reencryptKeySync;
exports.toYaml = toYaml;
exports.toYamlSync = toYamlSync;
exports.fromYaml = fromYaml;
exports.fromYamlSync = fromYamlSync;
exports.toHtml = toHtml;
exports.toHtmlSync = toHtmlSync;
exports.fromHtml = fromHtml;
exports.fromHtmlSync = fromHtmlSync;
exports.verifyYaml = verifyYaml;
exports.verifyYamlSync = verifyYamlSync;
exports.getPublicKey = getPublicKey;
exports.exportAgent = exportAgent;
exports.sharePublicKey = sharePublicKey;
exports.shareAgent = shareAgent;
exports.getAgentInfo = getAgentInfo;
exports.isLoaded = isLoaded;
exports.debugInfo = debugInfo;
exports.reset = reset;
exports.getDnsRecord = getDnsRecord;
exports.getWellKnownJson = getWellKnownJson;
exports.getSetupInstructions = getSetupInstructions;
exports.getSetupInstructionsSync = getSetupInstructionsSync;
exports.createAgreement = createAgreement;
exports.createAgreementSync = createAgreementSync;
exports.signAgreement = signAgreement;
exports.signAgreementSync = signAgreementSync;
exports.checkAgreement = checkAgreement;
exports.checkAgreementSync = checkAgreementSync;
exports.trustAgent = trustAgent;
exports.trustAgentWithKey = trustAgentWithKey;
exports.listTrustedAgents = listTrustedAgents;
exports.untrustAgent = untrustAgent;
exports.isTrusted = isTrusted;
exports.getTrustedAgent = getTrustedAgent;
exports.audit = audit;
exports.auditSync = auditSync;
exports.createAttestation = createAttestation;
exports.createAttestationSync = createAttestationSync;
exports.verifyAttestation = verifyAttestation;
exports.verifyAttestationSync = verifyAttestationSync;
exports.liftToAttestation = liftToAttestation;
exports.liftToAttestationSync = liftToAttestationSync;
exports.exportAttestationDsse = exportAttestationDsse;
exports.exportAttestationDsseSync = exportAttestationDsseSync;
const node_diagnostics_channel_1 = require("node:diagnostics_channel");
const index_1 = require("./index");
Object.defineProperty(exports, "JacsAgent", { enumerable: true, get: function () { return index_1.JacsAgent; } });
Object.defineProperty(exports, "hashString", { enumerable: true, get: function () { return index_1.hashString; } });
Object.defineProperty(exports, "createConfig", { enumerable: true, get: function () { return index_1.createConfig; } });
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const crypto_1 = require("crypto");
const deprecation_1 = require("./deprecation");
const verification_1 = require("./verification");
/** Node diagnostics_channel name for structured JACS security outcomes. */
exports.JACS_SECURITY_DIAGNOSTICS_CHANNEL = 'jacs.security';
const jacsSecurityChannel = (0, node_diagnostics_channel_1.channel)(exports.JACS_SECURITY_DIAGNOSTICS_CHANNEL);
class SignedEventReplayError extends Error {
    constructor(code, message) {
        super(`${code}: ${message}`);
        this.name = 'SignedEventReplayError';
        this.code = code;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
exports.SignedEventReplayError = SignedEventReplayError;
// =============================================================================
// Global State
// =============================================================================
let globalAgent = null;
/**
 * Auxiliary global JacsSimpleAgent used by the inline-text / image
 * module-level helpers (signText / verifyText / signImage / verifyImage /
 * extractMediaSignature). See JacsClient for the same pattern.
 */
let globalSimpleAgent = null;
let agentInfo = null;
let strictMode = false;
function adoptClientState(client) {
    const state = client;
    globalAgent = state.agent ?? null;
    globalSimpleAgent = state.simpleAgent ?? null;
    agentInfo = state.info ? { ...state.info } : null;
    strictMode = state._strict ?? strictMode;
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
    }
    return agentInfo;
}
function resolveStrict(explicit) {
    if (explicit !== undefined) {
        return explicit;
    }
    const envStrict = process.env.JACS_STRICT_MODE;
    return envStrict === 'true' || envStrict === '1';
}
function isStrict() {
    return strictMode;
}
function resolveCreatePaths(configPath, dataDirectory, keyDirectory) {
    const resolvedConfigPath = configPath ?? './jacs.config.json';
    const configDir = path.dirname(path.resolve(resolvedConfigPath));
    const cwd = path.resolve(process.cwd());
    return {
        configPath: resolvedConfigPath,
        dataDirectory: dataDirectory ?? (configDir === cwd ? './jacs_data' : path.join(configDir, 'jacs_data')),
        keyDirectory: keyDirectory ?? (configDir === cwd ? './jacs_keys' : path.join(configDir, 'jacs_keys')),
    };
}
function resolvePrivateKeyPassword(configPath, keyDirectory, explicitPassword) {
    return (0, index_1.resolvePrivateKeyPassword)(configPath ? path.resolve(configPath) : null, keyDirectory ?? null, explicitPassword ?? null);
}
function normalizeDocumentInput(document) {
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
function normalizeJsonInput(value) {
    return typeof value === 'string' ? value : JSON.stringify(value);
}
const DEFAULT_SIGNED_EVENT_MAX_AGE_SECONDS = 300;
const DEFAULT_REPLAY_STORE_TIMEOUT_MS = 5000;
const MAX_REPLAY_STORE_TIMEOUT_MS = 30000;
const MAX_NAPI_U32 = 4294967295;
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
]);
const SIGNED_EVENT_REPLAY_PREPARATION_FIELD_SET = new Set(SIGNED_EVENT_REPLAY_PREPARATION_FIELDS);
const NATIVE_JACS_AGENT_DIAGNOSTICS = index_1.JacsAgent.prototype.diagnostics;
const NATIVE_JACS_SIMPLE_AGENT_DIAGNOSTICS = index_1.JacsSimpleAgent.prototype.diagnostics;
function replayFailure(code, message) {
    return new SignedEventReplayError(code, message);
}
function publishReplayRejection(error) {
    const event = {
        level: 'warn',
        event: 'jacs_security_outcome',
        operation: 'signed_event_replay',
        outcome: 'rejected',
        error_code: error.code,
    };
    jacsSecurityChannel.publish(event);
}
function hasOwn(value, field) {
    return Object.prototype.hasOwnProperty.call(value, field);
}
function requirePositiveSafeInteger(value, name, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
        throw replayFailure('replay_store_invalid_result', `${name} must be a positive safe integer no greater than ${maximum}`);
    }
    return value;
}
function isWellFormedUtf16(value) {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff)) {
                return false;
            }
            index += 1;
        }
        else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return false;
        }
    }
    return true;
}
function requireWellFormedUtf16(value, name) {
    if (typeof value !== 'string' || !isWellFormedUtf16(value)) {
        throw replayFailure('replay_store_invalid_result', `${name} must be a well-formed UTF-16 string`);
    }
}
function advanceJsonString(raw, start) {
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
function skipJsonWhitespace(raw, start) {
    let index = start;
    while (index < raw.length && /\s/.test(raw[index])) {
        index += 1;
    }
    return index;
}
// JSON.parse overwrites duplicate object names. Native preparation is a flat
// object, so scan its top-level names as written before trusting the parsed
// value. Decoding each name also catches escaped aliases such as st\u0061tus.
function topLevelJsonObjectKeys(raw) {
    const keys = [];
    const seen = new Set();
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
        const key = JSON.parse(raw.slice(keyStart, index));
        if (seen.has(key)) {
            throw replayFailure('replay_store_invalid_result', `native replay preparation contains duplicate field ${key}`);
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
            }
            else if (character === '}' || character === ']') {
                if (nesting === 0) {
                    break;
                }
                nesting -= 1;
            }
            else if (character === ',' && nesting === 0) {
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
function daysInUtcMonth(year, month) {
    if (month === 2) {
        const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
        return leap ? 29 : 28;
    }
    return [4, 6, 9, 11].includes(month) ? 30 : 31;
}
function parseStrictRfc3339UnixSeconds(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
    if (!match) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation timestamp must be strict RFC 3339');
    }
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const offsetHour = match[8] === 'Z' ? 0 : Number(match[10]);
    const offsetMinute = match[8] === 'Z' ? 0 : Number(match[11]);
    if (year < 1970
        || month < 1 || month > 12
        || day < 1 || day > daysInUtcMonth(year, month)
        || hour > 23 || minute > 59 || second > 59
        || offsetHour > 23 || offsetMinute > 59) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation timestamp is not a valid RFC 3339 instant');
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
        throw replayFailure('replay_store_invalid_result', 'native replay preparation timestamp is outside the supported range');
    }
    return unixSeconds;
}
function isNativeReplayAgent(agent) {
    try {
        if (agent instanceof index_1.JacsAgent) {
            NATIVE_JACS_AGENT_DIAGNOSTICS.call(agent);
            return true;
        }
        if (agent instanceof index_1.JacsSimpleAgent) {
            NATIVE_JACS_SIMPLE_AGENT_DIAGNOSTICS.call(agent);
            return true;
        }
        return false;
    }
    catch {
        return false;
    }
}
function isAsyncFunction(value) {
    try {
        const source = Function.prototype.toString.call(value);
        return Object.prototype.toString.call(value) === '[object AsyncFunction]'
            && /^\s*async(?:\s+function\b|\s*\(|\s+[A-Za-z_$])/.test(source);
    }
    catch {
        return false;
    }
}
function validateSharedReplayStore(store) {
    if (!store || (typeof store !== 'object' && typeof store !== 'function')) {
        throw replayFailure('replay_store_not_shared', 'signed-event delivery requires a shared replay store');
    }
    let scope;
    let name;
    let consume;
    try {
        const runtimeStore = store;
        scope = runtimeStore.scope;
        name = runtimeStore.name;
        consume = runtimeStore.consume;
    }
    catch {
        throw replayFailure('replay_store_unavailable', 'shared replay store metadata could not be read');
    }
    if (scope !== 'shared') {
        throw replayFailure('replay_store_not_shared', 'signed-event delivery requires store.scope === "shared"');
    }
    if (typeof name !== 'string' || name.trim().length === 0) {
        throw replayFailure('replay_store_invalid_result', 'shared replay store must provide a nonblank string name');
    }
    if (typeof consume !== 'function') {
        throw replayFailure('replay_store_unavailable', 'shared replay store must provide consume(key, ttlSeconds, signal)');
    }
    if (!isAsyncFunction(consume)) {
        throw replayFailure('replay_store_invalid_result', 'shared replay store consume must be declared async');
    }
    return {
        receiver: store,
        consume: consume,
    };
}
function parseReplayPreparation(rawPreparation, immutableEventJson, maxAgeSeconds) {
    let parsed;
    try {
        parsed = JSON.parse(rawPreparation);
    }
    catch {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation was not valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation must be a JSON object');
    }
    const preparation = parsed;
    const rawFields = topLevelJsonObjectKeys(rawPreparation);
    const parsedFields = Object.keys(preparation);
    if (rawFields.length !== SIGNED_EVENT_REPLAY_PREPARATION_FIELDS.length
        || parsedFields.length !== SIGNED_EVENT_REPLAY_PREPARATION_FIELDS.length
        || rawFields.some((field) => !SIGNED_EVENT_REPLAY_PREPARATION_FIELD_SET.has(field))
        || parsedFields.some((field) => !SIGNED_EVENT_REPLAY_PREPARATION_FIELD_SET.has(field))) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation fields do not exactly match contract version 1');
    }
    if (preparation.contractVersion !== 1
        || preparation.status !== 'crypto_verified_replay_pending'
        || preparation.cryptographicallyVerified !== true
        || preparation.freshnessVerified !== true
        || preparation.replayConsumed !== false) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation did not satisfy the fixed contract values');
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
            throw replayFailure('replay_store_invalid_result', `native replay preparation field ${field} must be a non-empty well-formed string`);
        }
    }
    const expectedSha256 = (0, crypto_1.createHash)('sha256')
        .update(immutableEventJson, 'utf8')
        .digest('hex');
    if (!/^[0-9a-f]{64}$/.test(preparation.eventSha256)
        || preparation.eventSha256 !== expectedSha256) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation did not bind the exact signed-event UTF-8 bytes');
    }
    const signerId = preparation.signerId;
    const documentId = preparation.documentId;
    const replayScope = `signed-event:${signerId}`;
    const expectedReplayKey = `jacs-replay-v1:${Buffer.byteLength(replayScope, 'utf8')}:${replayScope}:${documentId}`;
    if (preparation.replayKey !== expectedReplayKey) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation replay key does not match signer and document');
    }
    const maximumReplayTtlSeconds = maxAgeSeconds + MAX_SIGNED_EVENT_FUTURE_SKEW_SECONDS + 1;
    const replayTtlSeconds = requirePositiveSafeInteger(preparation.replayTtlSeconds, 'replayTtlSeconds', maximumReplayTtlSeconds);
    const expiresAtUnixSeconds = requirePositiveSafeInteger(preparation.expiresAtUnixSeconds, 'expiresAtUnixSeconds');
    const issuedAtUnixSeconds = parseStrictRfc3339UnixSeconds(preparation.timestamp);
    const nowUnixSeconds = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < 0) {
        throw replayFailure('replay_store_invalid_result', 'system clock is outside the supported range');
    }
    if (issuedAtUnixSeconds > nowUnixSeconds + MAX_SIGNED_EVENT_FUTURE_SKEW_SECONDS) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation timestamp exceeds allowed future skew');
    }
    const expectedExpiry = issuedAtUnixSeconds + maxAgeSeconds;
    if (!Number.isSafeInteger(expectedExpiry) || expectedExpiry !== expiresAtUnixSeconds) {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation expiry does not match timestamp plus maxAgeSeconds');
    }
    if (nowUnixSeconds > expiresAtUnixSeconds) {
        throw replayFailure('signed_event_expired', 'signed event expired before replay consumption');
    }
    const minimumSafeTtl = expiresAtUnixSeconds - nowUnixSeconds + 1;
    if (replayTtlSeconds < minimumSafeTtl) {
        throw replayFailure('replay_store_invalid_result', 'native replay TTL ends before the signed event absolute expiry');
    }
    return preparation;
}
async function consumeReplayWithTimeout(store, replayKey, replayTtlSeconds, timeoutMs) {
    const controller = new AbortController();
    let timedOut = false;
    let timer;
    const timeoutError = replayFailure('replay_store_timeout', `shared replay store did not respond within ${timeoutMs}ms`);
    const timeout = new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
            timedOut = true;
            controller.abort();
            reject(timeoutError);
        }, timeoutMs);
    });
    const consumption = Promise.resolve().then(() => store.consume.call(store.receiver, replayKey, replayTtlSeconds, controller.signal));
    try {
        return await Promise.race([consumption, timeout]);
    }
    catch (error) {
        if (timedOut || error === timeoutError) {
            throw timeoutError;
        }
        throw replayFailure('replay_store_unavailable', 'shared replay store consume failed');
    }
    finally {
        if (timer !== undefined) {
            clearTimeout(timer);
        }
    }
}
function requireQuickstartIdentity(options) {
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
function toQuickstartInfo(info) {
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
function createRawDocumentPayload(jacsType, extra) {
    return JSON.stringify({
        jacsType,
        jacsLevel: 'raw',
        ...extra,
    });
}
function createDocumentImpl(agent, docContent, filePath, embed, isSync) {
    if (isSync) {
        return agent.createDocumentSync(docContent, null, null, true, filePath, embed);
    }
    return agent.createDocument(docContent, null, null, true, filePath, embed);
}
function makeVerificationSuccess(signerId = '') {
    return {
        valid: true,
        signerId,
        timestamp: '',
        attachments: [],
        errors: [],
    };
}
function makeVerificationFailure(e, strictPrefix, signerId = '') {
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
function invalidDocumentIdResult(documentId) {
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
function extractAttachmentsFromDocument(doc) {
    return (doc.jacsFiles || []).map((f) => ({
        filename: f.path || f.filename || '',
        mimeType: f.mimetype || f.mimeType || 'application/octet-stream',
        hash: f.sha256 || '',
        embedded: f.embed || false,
        content: (f.contents || f.content) ? Buffer.from(f.contents || f.content, 'base64') : undefined,
    }));
}
function parseCreateResult(resultJson, options) {
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
function parseSignedResult(result) {
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
}
function requireAgent() {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
    }
    return globalAgent;
}
async function withAgentPassword(operation) {
    const agent = requireAgent();
    return operation(agent);
}
function withAgentPasswordSync(operation) {
    const agent = requireAgent();
    return operation(agent);
}
function verifyImpl(signedDocument, agent, isSync) {
    const trimmed = signedDocument.trim();
    if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
        const result = {
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
    let doc;
    try {
        doc = JSON.parse(signedDocument);
    }
    catch (e) {
        const result = {
            valid: false,
            signerId: '',
            timestamp: '',
            attachments: [],
            errors: [`Invalid JSON: ${e}`],
        };
        return isSync ? result : Promise.resolve(result);
    }
    const extractAttachments = () => extractAttachmentsFromDocument(doc);
    const signatureMetadata = (0, verification_1.authenticatedSignatureMetadata)(doc);
    const makeSuccess = () => ({
        valid: true,
        data: doc.content,
        signerId: signatureMetadata.signerId,
        timestamp: signatureMetadata.timestamp,
        attachments: extractAttachments(),
        errors: [],
    });
    const makeFailure = (e) => {
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
            (0, verification_1.requireLiteralTrueVerification)(verified, 'Native document verification');
            return makeSuccess();
        }
        catch (e) {
            return makeFailure(e);
        }
    }
    else {
        return agent.verifyDocument(signedDocument)
            .then((verified) => {
            (0, verification_1.requireLiteralTrueVerification)(verified, 'Native document verification');
            return makeSuccess();
        })
            .catch((e) => makeFailure(e));
    }
}
function ensurePassword(configPath, keyDirectory) {
    return (0, index_1.quickstartPrivateKeyPassword)(configPath ? path.resolve(configPath) : null, keyDirectory ?? null);
}
/**
 * Quickstart: loads or creates a persistent agent.
 * @returns Promise<QuickstartInfo>
 */
async function quickstart(options) {
    const { JacsClient } = require('./client');
    const client = await JacsClient.quickstart(options);
    return toQuickstartInfo(adoptClientState(client));
}
/**
 * Quickstart (sync variant, blocks event loop).
 */
function quickstartSync(options) {
    const { JacsClient } = require('./client');
    const client = JacsClient.quickstartSync(options);
    return toQuickstartInfo(adoptClientState(client));
}
function resolveCreatePassword(options) {
    const p = resolvePrivateKeyPassword(options.configPath ?? null, options.keyDirectory ?? null, options.password ?? null);
    if (!p) {
        throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
    }
    return p;
}
function createNativeArgs(options, password) {
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
async function create(options) {
    const password = resolveCreatePassword(options);
    const normalizedOptions = {
        ...options,
        ...resolveCreatePaths(options.configPath ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null),
    };
    const resultJson = await (0, index_1.createAgent)(...createNativeArgs(normalizedOptions, password));
    return parseCreateResult(resultJson, normalizedOptions);
}
/**
 * Creates a new JACS agent (sync, blocks event loop).
 */
function createSync(options) {
    const password = resolveCreatePassword(options);
    const normalizedOptions = {
        ...options,
        ...resolveCreatePaths(options.configPath ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null),
    };
    const resultJson = (0, index_1.createAgentSync)(...createNativeArgs(normalizedOptions, password));
    return parseCreateResult(resultJson, normalizedOptions);
}
/**
 * Loads an existing agent from a configuration file.
 */
async function load(configPath, options) {
    const { JacsClient } = require('./client');
    const client = new JacsClient({ strict: options?.strict });
    await client.load(configPath, options);
    return adoptClientState(client);
}
/**
 * Loads an existing agent (sync, blocks event loop).
 */
function loadSync(configPath, options) {
    const { JacsClient } = require('./client');
    const client = new JacsClient({ strict: options?.strict });
    client.loadSync(configPath, options);
    return adoptClientState(client);
}
/**
 * Verifies the currently loaded agent's integrity.
 */
async function verifySelf() {
    const agent = requireAgent();
    try {
        const verified = await agent.verifyAgent();
        (0, verification_1.requireLiteralTrueVerification)(verified, 'Native agent verification');
        return makeVerificationSuccess(agentInfo?.agentId || '');
    }
    catch (e) {
        return makeVerificationFailure(e, 'Self-verification failed');
    }
}
/**
 * Verifies the currently loaded agent's integrity (sync).
 */
function verifySelfSync() {
    const agent = requireAgent();
    try {
        const verified = agent.verifyAgentSync();
        (0, verification_1.requireLiteralTrueVerification)(verified, 'Native agent verification');
        return makeVerificationSuccess(agentInfo?.agentId || '');
    }
    catch (e) {
        return makeVerificationFailure(e, 'Self-verification failed');
    }
}
/**
 * Signs arbitrary data with the legacy signed-message type label.
 */
async function signMessage(data) {
    const docContent = createRawDocumentPayload('message', { content: data });
    return withAgentPassword(async (agent) => {
        const result = await createDocumentImpl(agent, docContent, null, null, false);
        return parseSignedResult(result);
    });
}
/**
 * Signs arbitrary data (sync, blocks event loop).
 */
function signMessageSync(data) {
    const docContent = createRawDocumentPayload('message', { content: data });
    return withAgentPasswordSync((agent) => {
        const result = createDocumentImpl(agent, docContent, null, null, true);
        return parseSignedResult(result);
    });
}
/**
 * Updates the agent document with new data and re-signs it.
 */
async function updateAgent(newAgentData) {
    return withAgentPassword((agent) => agent.updateAgent(normalizeJsonInput(newAgentData)));
}
/**
 * Updates the agent document (sync, blocks event loop).
 */
function updateAgentSync(newAgentData) {
    return withAgentPasswordSync((agent) => agent.updateAgentSync(normalizeJsonInput(newAgentData)));
}
/**
 * Updates an existing document with new data and re-signs it.
 */
async function updateDocument(documentId, newDocumentData, attachments, embed) {
    const dataString = normalizeJsonInput(newDocumentData);
    return withAgentPassword(async (agent) => {
        const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
        return parseSignedResult(result);
    });
}
/**
 * Updates an existing document (sync, blocks event loop).
 */
function updateDocumentSync(documentId, newDocumentData, attachments, embed) {
    const dataString = normalizeJsonInput(newDocumentData);
    return withAgentPasswordSync((agent) => {
        const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
        return parseSignedResult(result);
    });
}
/**
 * Signs a file with optional content embedding.
 */
async function signFile(filePath, embed = false) {
    requireAgent();
    if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }
    const docContent = createRawDocumentPayload('file', {
        filename: path.basename(filePath),
    });
    return withAgentPassword(async (agent) => {
        const result = await createDocumentImpl(agent, docContent, filePath, embed, false);
        return parseSignedResult(result);
    });
}
/**
 * Signs a file (sync, blocks event loop).
 */
function signFileSync(filePath, embed = false) {
    requireAgent();
    if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }
    const docContent = createRawDocumentPayload('file', {
        filename: path.basename(filePath),
    });
    return withAgentPasswordSync((agent) => {
        const result = createDocumentImpl(agent, docContent, filePath, embed, true);
        return parseSignedResult(result);
    });
}
function requireSimpleAgent() {
    if (!globalSimpleAgent) {
        throw new Error('No agent loaded. Call quickstart({ name, domain }), load(), or create() first.');
    }
    return globalSimpleAgent;
}
/** Constant accessor for the {@link AgreementV2Role} values. */
exports.AgreementV2Role = {
    SIGNER: 'signer',
    WITNESS: 'witness',
    NOTARY: 'notary',
};
async function createAgreementV2(input) {
    return requireSimpleAgent().createAgreementV2(normalizeJsonInput(input));
}
function createAgreementV2Sync(input) {
    return requireSimpleAgent().createAgreementV2Sync(normalizeJsonInput(input));
}
async function applyAgreementV2(document, mutation) {
    return requireSimpleAgent().applyAgreementV2(normalizeDocumentInput(document), normalizeJsonInput(mutation));
}
function applyAgreementV2Sync(document, mutation) {
    return requireSimpleAgent().applyAgreementV2Sync(normalizeDocumentInput(document), normalizeJsonInput(mutation));
}
async function signAgreementV2(document, role = 'signer') {
    return requireSimpleAgent().signAgreementV2(normalizeDocumentInput(document), role);
}
function signAgreementV2Sync(document, role = 'signer') {
    return requireSimpleAgent().signAgreementV2Sync(normalizeDocumentInput(document), role);
}
async function verifyAgreementV2(document) {
    return requireSimpleAgent().verifyAgreementV2(normalizeDocumentInput(document));
}
function verifyAgreementV2Sync(document) {
    return requireSimpleAgent().verifyAgreementV2Sync(normalizeDocumentInput(document));
}
/**
 * Convenience wrapper over {@link verifyAgreementV2} that types the parsed
 * report. Identical runtime behaviour; only the static type is narrowed.
 */
async function verifyAgreementV2Typed(document) {
    return (await verifyAgreementV2(document));
}
/** Sync variant of {@link verifyAgreementV2Typed}. */
function verifyAgreementV2TypedSync(document) {
    return verifyAgreementV2Sync(document);
}
async function detectAgreementV2BranchConflict(base, left, right) {
    return requireSimpleAgent().detectAgreementV2BranchConflict(normalizeDocumentInput(base), normalizeDocumentInput(left), normalizeDocumentInput(right));
}
function detectAgreementV2BranchConflictSync(base, left, right) {
    return requireSimpleAgent().detectAgreementV2BranchConflictSync(normalizeDocumentInput(base), normalizeDocumentInput(left), normalizeDocumentInput(right));
}
/**
 * Convenience wrapper over {@link detectAgreementV2BranchConflict} that types
 * the parsed analysis. Identical runtime behaviour.
 */
async function detectAgreementV2BranchConflictTyped(base, left, right) {
    return (await detectAgreementV2BranchConflict(base, left, right));
}
/** Sync variant of {@link detectAgreementV2BranchConflictTyped}. */
function detectAgreementV2BranchConflictTypedSync(base, left, right) {
    return detectAgreementV2BranchConflictSync(base, left, right);
}
async function mergeAgreementV2TranscriptBranches(base, left, right) {
    return requireSimpleAgent().mergeAgreementV2TranscriptBranches(normalizeDocumentInput(base), normalizeDocumentInput(left), normalizeDocumentInput(right));
}
function mergeAgreementV2TranscriptBranchesSync(base, left, right) {
    return requireSimpleAgent().mergeAgreementV2TranscriptBranchesSync(normalizeDocumentInput(base), normalizeDocumentInput(left), normalizeDocumentInput(right));
}
async function resolveAgreementV2BranchConflict(base, previous, side, mutation) {
    return requireSimpleAgent().resolveAgreementV2BranchConflict(normalizeDocumentInput(base), normalizeDocumentInput(previous), normalizeDocumentInput(side), normalizeJsonInput(mutation));
}
function resolveAgreementV2BranchConflictSync(base, previous, side, mutation) {
    return requireSimpleAgent().resolveAgreementV2BranchConflictSync(normalizeDocumentInput(base), normalizeDocumentInput(previous), normalizeDocumentInput(side), normalizeJsonInput(mutation));
}
async function signText(filePath, opts) {
    return requireSimpleAgent().signText(filePath, opts?.noBackup ?? false);
}
function signTextSync(filePath, opts) {
    return requireSimpleAgent().signTextSync(filePath, opts?.noBackup ?? false);
}
async function verifyText(filePath, opts) {
    return requireSimpleAgent().verifyText(filePath, {
        strict: opts?.strict ?? false,
        keyDir: opts?.keyDir,
    });
}
function verifyTextSync(filePath, opts) {
    return requireSimpleAgent().verifyTextSync(filePath, {
        strict: opts?.strict ?? false,
        keyDir: opts?.keyDir,
    });
}
async function signImage(inputPath, outputPath, opts) {
    return requireSimpleAgent().signImage(inputPath, outputPath, {
        robust: opts?.robust ?? false,
        format: opts?.format,
        refuseOverwrite: opts?.refuseOverwrite ?? false,
    });
}
function signImageSync(inputPath, outputPath, opts) {
    return requireSimpleAgent().signImageSync(inputPath, outputPath, {
        robust: opts?.robust ?? false,
        format: opts?.format,
        refuseOverwrite: opts?.refuseOverwrite ?? false,
    });
}
async function verifyImage(filePath, opts) {
    return requireSimpleAgent().verifyImage(filePath, {
        strict: opts?.strict ?? false,
        keyDir: opts?.keyDir,
        robust: opts?.robust ?? false,
    });
}
function verifyImageSync(filePath, opts) {
    return requireSimpleAgent().verifyImageSync(filePath, {
        strict: opts?.strict ?? false,
        keyDir: opts?.keyDir,
        robust: opts?.robust ?? false,
    });
}
async function extractMediaSignature(filePath, opts) {
    return requireSimpleAgent().extractMediaSignature(filePath, {
        rawPayload: opts?.rawPayload ?? false,
    });
}
function extractMediaSignatureSync(filePath, opts) {
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
async function unwrapSignedEventWithReplayStoreImpl(agent, eventJson, serverKeysJson, store, options = {}) {
    requireWellFormedUtf16(eventJson, 'eventJson');
    requireWellFormedUtf16(serverKeysJson, 'serverKeysJson');
    if (!isNativeReplayAgent(agent)) {
        throw replayFailure('replay_store_invalid_result', 'agent must be a native JacsAgent or JacsSimpleAgent instance');
    }
    const validatedStore = validateSharedReplayStore(store);
    const maxAgeSeconds = requirePositiveSafeInteger(options.maxAgeSeconds ?? DEFAULT_SIGNED_EVENT_MAX_AGE_SECONDS, 'maxAgeSeconds', MAX_NAPI_U32);
    const requestedTimeoutMs = requirePositiveSafeInteger(options.timeoutMs ?? DEFAULT_REPLAY_STORE_TIMEOUT_MS, 'timeoutMs');
    const timeoutMs = Math.min(requestedTimeoutMs, MAX_REPLAY_STORE_TIMEOUT_MS);
    const immutableEventJson = eventJson;
    // Do not parse the event or inspect its data before native cryptographic and
    // freshness verification produces a no-payload preparation claim.
    const rawPreparation = await agent.prepareSignedEventReplay(immutableEventJson, serverKeysJson, maxAgeSeconds);
    if (typeof rawPreparation !== 'string') {
        throw replayFailure('replay_store_invalid_result', 'native replay preparation must be returned as a JSON string');
    }
    const preparation = parseReplayPreparation(rawPreparation, immutableEventJson, maxAgeSeconds);
    const consumed = await consumeReplayWithTimeout(validatedStore, preparation.replayKey, preparation.replayTtlSeconds, timeoutMs);
    if (consumed === false) {
        throw replayFailure('replay_duplicate', 'signed event replay key was already consumed');
    }
    if (consumed !== true) {
        throw replayFailure('replay_store_invalid_result', 'shared replay store consume must return literal true or false');
    }
    if (Math.floor(Date.now() / 1000) > preparation.expiresAtUnixSeconds) {
        throw replayFailure('signed_event_expired', 'signed event expired during replay consumption');
    }
    // The string passed to native verification is immutable. Parse that same
    // value only after atomic replay consumption succeeds.
    let event;
    try {
        event = JSON.parse(immutableEventJson);
    }
    catch {
        throw replayFailure('replay_store_invalid_result', 'verified signed-event JSON could not be parsed after replay consumption');
    }
    if (!event || typeof event !== 'object' || Array.isArray(event) || !hasOwn(event, 'data')) {
        throw replayFailure('replay_store_invalid_result', 'verified signed event did not contain data');
    }
    return {
        status: 'verified',
        verified: true,
        replayConsumed: true,
        data: event.data,
        signerId: preparation.signerId,
        timestamp: preparation.timestamp,
        algorithm: preparation.algorithm,
        documentId: preparation.documentId,
    };
}
async function unwrapSignedEventWithReplayStore(agent, eventJson, serverKeysJson, store, options = {}) {
    try {
        return await unwrapSignedEventWithReplayStoreImpl(agent, eventJson, serverKeysJson, store, options);
    }
    catch (error) {
        if (error instanceof SignedEventReplayError) {
            publishReplayRejection(error);
        }
        throw error;
    }
}
/**
 * Verifies a signed document and extracts its content.
 */
async function verify(signedDocument) {
    const agent = requireAgent();
    return verifyImpl(signedDocument, agent, false);
}
/**
 * Verifies a signed document (sync, blocks event loop).
 */
function verifySync(signedDocument) {
    const agent = requireAgent();
    return verifyImpl(signedDocument, agent, true);
}
/**
 * Verify a signed JACS document without loading an agent.
 */
function verifyStandalone(signedDocument, options) {
    const doc = typeof signedDocument === 'string' ? signedDocument : JSON.stringify(signedDocument);
    const r = (0, index_1.verifyDocumentStandalone)(doc, options?.keyResolution ?? undefined, options?.dataDirectory ?? undefined, options?.keyDirectory ?? undefined);
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
async function verifyById(documentId) {
    const agent = requireAgent();
    if (!documentId.includes(':')) {
        return invalidDocumentIdResult(documentId);
    }
    try {
        const verified = await agent.verifyDocumentById(documentId);
        (0, verification_1.requireLiteralTrueVerification)(verified, 'Native stored-document verification');
        const storedJson = await agent.getDocumentById(documentId);
        const stored = JSON.parse(storedJson);
        const metadata = (0, verification_1.authenticatedSignatureMetadata)(stored);
        return {
            ...makeVerificationSuccess(metadata.signerId),
            timestamp: metadata.timestamp,
            attachments: extractAttachmentsFromDocument(stored || {}),
        };
    }
    catch (e) {
        return makeVerificationFailure(e, 'Verification failed');
    }
}
/**
 * Verifies a document by its storage ID (sync, blocks event loop).
 */
function verifyByIdSync(documentId) {
    const agent = requireAgent();
    if (!documentId.includes(':')) {
        return invalidDocumentIdResult(documentId);
    }
    try {
        const verified = agent.verifyDocumentByIdSync(documentId);
        (0, verification_1.requireLiteralTrueVerification)(verified, 'Native stored-document verification');
        const storedJson = agent.getDocumentByIdSync(documentId);
        const stored = JSON.parse(storedJson);
        const metadata = (0, verification_1.authenticatedSignatureMetadata)(stored);
        return {
            ...makeVerificationSuccess(metadata.signerId),
            timestamp: metadata.timestamp,
            attachments: extractAttachmentsFromDocument(stored || {}),
        };
    }
    catch (e) {
        return makeVerificationFailure(e, 'Verification failed');
    }
}
/**
 * Re-encrypt the agent's private key with a new password.
 */
async function reencryptKey(oldPassword, newPassword) {
    const agent = requireAgent();
    await agent.reencryptKey(oldPassword, newPassword);
}
/**
 * Re-encrypt the agent's private key (sync, blocks event loop).
 */
function reencryptKeySync(oldPassword, newPassword) {
    const agent = requireAgent();
    agent.reencryptKeySync(oldPassword, newPassword);
}
// =============================================================================
// Format Conversion (YAML / HTML)
// =============================================================================
/**
 * Convert a JSON string to YAML (async).
 */
async function toYaml(jsonStr) {
    return requireAgent().toYaml(jsonStr);
}
/**
 * Convert a JSON string to YAML (sync).
 */
function toYamlSync(jsonStr) {
    return requireAgent().toYamlSync(jsonStr);
}
/**
 * Convert a YAML string to pretty-printed JSON (async).
 */
async function fromYaml(yamlStr) {
    return requireAgent().fromYaml(yamlStr);
}
/**
 * Convert a YAML string to pretty-printed JSON (sync).
 */
function fromYamlSync(yamlStr) {
    return requireAgent().fromYamlSync(yamlStr);
}
/**
 * Convert a JSON string to a self-contained HTML document (async).
 */
async function toHtml(jsonStr) {
    return requireAgent().toHtml(jsonStr);
}
/**
 * Convert a JSON string to a self-contained HTML document (sync).
 */
function toHtmlSync(jsonStr) {
    return requireAgent().toHtmlSync(jsonStr);
}
/**
 * Extract JSON from an HTML document produced by toHtml() (async).
 */
async function fromHtml(htmlStr) {
    return requireAgent().fromHtml(htmlStr);
}
/**
 * Extract JSON from an HTML document produced by toHtml() (sync).
 */
function fromHtmlSync(htmlStr) {
    return requireAgent().fromHtmlSync(htmlStr);
}
/**
 * Convert YAML to JSON and verify the resulting document (async).
 */
async function verifyYaml(yamlStr) {
    return requireAgent().verifyYaml(yamlStr);
}
/**
 * Convert YAML to JSON and verify the resulting document (sync).
 */
function verifyYamlSync(yamlStr) {
    return requireAgent().verifyYamlSync(yamlStr);
}
// =============================================================================
// Pure sync helpers (no NAPI calls, stay sync-only)
// =============================================================================
function getPublicKey() {
    return requireAgent().getPublicKeyPem();
}
function exportAgent() {
    return requireAgent().exportAgent();
}
/** @deprecated Use getPublicKey() instead. */
function sharePublicKey() {
    (0, deprecation_1.warnDeprecated)('sharePublicKey', 'getPublicKey');
    return getPublicKey();
}
/** @deprecated Use exportAgent() instead. */
function shareAgent() {
    (0, deprecation_1.warnDeprecated)('shareAgent', 'exportAgent');
    return exportAgent();
}
function getAgentInfo() {
    return agentInfo;
}
function isLoaded() {
    return globalAgent !== null;
}
function debugInfo() {
    if (!globalAgent) {
        return { jacs_version: 'unknown', agent_loaded: false };
    }
    try {
        return JSON.parse(globalAgent.diagnostics());
    }
    catch {
        return { jacs_version: 'unknown', agent_loaded: false };
    }
}
function reset() {
    if (globalAgent) {
        try {
            globalAgent.setPrivateKeyPassword(null);
        }
        catch {
            // Best-effort cleanup; the instance is being discarded anyway.
        }
    }
    globalAgent = null;
    agentInfo = null;
    strictMode = false;
}
function getDnsRecord(domain, ttl = 3600) {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
    }
    const agentDoc = JSON.parse(exportAgent());
    const jacsId = agentDoc.jacsId || agentDoc.agentId || '';
    const publicKeyHash = agentDoc.jacsSignature?.publicKeyHash ||
        agentDoc.jacsSignature?.['publicKeyHash'] ||
        '';
    const d = domain.replace(/\.$/, '');
    const owner = `_v1.agent.jacs.${d}.`;
    const txt = `v=jacs; jacs_agent_id=${jacsId}; alg=SHA-256; enc=base64; jac_public_key_hash=${publicKeyHash}`;
    return `${owner} ${ttl} IN TXT "${txt}"`;
}
function getWellKnownJson() {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart({ name, domain }) for zero-config setup, or load() for a persistent agent.');
    }
    const agentDoc = JSON.parse(exportAgent());
    const jacsId = agentDoc.jacsId || agentDoc.agentId || '';
    const publicKeyHash = agentDoc.jacsSignature?.publicKeyHash ||
        agentDoc.jacsSignature?.['publicKeyHash'] ||
        '';
    let publicKey = '';
    try {
        publicKey = getPublicKey();
    }
    catch {
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
async function getSetupInstructions(domain, ttl = 3600) {
    const agent = requireAgent();
    const json = await agent.getSetupInstructions(domain, ttl);
    return JSON.parse(json);
}
function getSetupInstructionsSync(domain, ttl = 3600) {
    const agent = requireAgent();
    const json = agent.getSetupInstructionsSync(domain, ttl);
    return JSON.parse(json);
}
async function createAgreement(document, agentIds, question, context, fieldName) {
    const docString = normalizeDocumentInput(document);
    return withAgentPassword(async (agent) => {
        const result = await agent.createAgreement(docString, agentIds, question || null, context || null, fieldName || null);
        return parseSignedResult(result);
    });
}
function createAgreementSync(document, agentIds, question, context, fieldName) {
    const docString = normalizeDocumentInput(document);
    return withAgentPasswordSync((agent) => {
        const result = agent.createAgreementSync(docString, agentIds, question || null, context || null, fieldName || null);
        return parseSignedResult(result);
    });
}
async function signAgreement(document, fieldName) {
    const docString = normalizeDocumentInput(document);
    return withAgentPassword(async (agent) => {
        const result = await agent.signAgreement(docString, fieldName || null);
        return parseSignedResult(result);
    });
}
function signAgreementSync(document, fieldName) {
    const docString = normalizeDocumentInput(document);
    return withAgentPasswordSync((agent) => {
        const result = agent.signAgreementSync(docString, fieldName || null);
        return parseSignedResult(result);
    });
}
async function checkAgreement(document, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = await agent.checkAgreement(docString, fieldName || null);
    return (0, verification_1.normalizeAgreementStatus)(JSON.parse(result));
}
function checkAgreementSync(document, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = agent.checkAgreementSync(docString, fieldName || null);
    return (0, verification_1.normalizeAgreementStatus)(JSON.parse(result));
}
// =============================================================================
// Trust Store Functions (sync-only — fast local file lookups)
// =============================================================================
function trustAgent(agentJson) {
    return (0, index_1.trustAgent)(agentJson);
}
function trustAgentWithKey(agentJson, publicKeyPem) {
    if (!publicKeyPem || !publicKeyPem.trim()) {
        throw new Error('publicKeyPem cannot be empty');
    }
    return (0, index_1.trustAgentWithKey)(agentJson, publicKeyPem);
}
function listTrustedAgents() {
    return (0, index_1.listTrustedAgents)();
}
function untrustAgent(agentId) {
    (0, index_1.untrustAgent)(agentId);
}
function isTrusted(agentId) {
    return (0, index_1.isTrusted)(agentId);
}
function getTrustedAgent(agentId) {
    return (0, index_1.getTrustedAgent)(agentId);
}
async function audit(options) {
    const json = await (0, index_1.audit)(options?.configPath ?? undefined, options?.recentN ?? undefined);
    return JSON.parse(json);
}
function auditSync(options) {
    const json = (0, index_1.auditSync)(options?.configPath ?? undefined, options?.recentN ?? undefined);
    return JSON.parse(json);
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
async function createAttestation(params) {
    return withAgentPassword(async (agent) => {
        const raw = await agent.createAttestation(JSON.stringify(params));
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
function createAttestationSync(params) {
    return withAgentPasswordSync((agent) => {
        const raw = agent.createAttestationSync(JSON.stringify(params));
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
async function verifyAttestation(attestationJson, opts) {
    const agent = requireAgent();
    const doc = JSON.parse(attestationJson);
    const docKey = `${doc.jacsId}:${doc.jacsVersion}`;
    let resultJson;
    if (opts?.full) {
        resultJson = await agent.verifyAttestationFull(docKey);
    }
    else {
        resultJson = await agent.verifyAttestation(docKey);
    }
    return (0, verification_1.normalizeAttestationVerificationResult)(JSON.parse(resultJson));
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
function verifyAttestationSync(attestationJson, opts) {
    const agent = requireAgent();
    const doc = JSON.parse(attestationJson);
    const docKey = `${doc.jacsId}:${doc.jacsVersion}`;
    let resultJson;
    if (opts?.full) {
        resultJson = agent.verifyAttestationFullSync(docKey);
    }
    else {
        resultJson = agent.verifyAttestationSync(docKey);
    }
    return (0, verification_1.normalizeAttestationVerificationResult)(JSON.parse(resultJson));
}
/**
 * Lift a signed document into an attestation (async).
 *
 * @param signedDocJson - Raw JSON string of the signed document.
 * @param claims - Array of claim objects.
 * @returns The lifted attestation as a SignedDocument.
 */
async function liftToAttestation(signedDocJson, claims) {
    return withAgentPassword(async (agent) => {
        const raw = await agent.liftToAttestation(signedDocJson, JSON.stringify(claims));
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
function liftToAttestationSync(signedDocJson, claims) {
    return withAgentPasswordSync((agent) => {
        const raw = agent.liftToAttestationSync(signedDocJson, JSON.stringify(claims));
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
async function exportAttestationDsse(attestationJson) {
    return withAgentPassword(async (agent) => {
        const raw = await agent.exportAttestationDsse(attestationJson);
        return JSON.parse(raw);
    });
}
/**
 * Export an attestation as a DSSE (Dead Simple Signing Envelope) (sync).
 *
 * @param attestationJson - Raw JSON string of the attestation document.
 * @returns The DSSE envelope as a parsed object.
 */
function exportAttestationDsseSync(attestationJson) {
    return withAgentPasswordSync((agent) => {
        const raw = agent.exportAttestationDsseSync(attestationJson);
        return JSON.parse(raw);
    });
}
//# sourceMappingURL=simple.js.map
