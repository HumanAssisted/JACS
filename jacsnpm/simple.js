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
exports.MAX_VERIFY_DOCUMENT_BYTES = exports.MAX_VERIFY_URL_LEN = exports.createConfig = exports.hashString = exports.JacsAgent = void 0;
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
exports.verify = verify;
exports.verifySync = verifySync;
exports.verifyStandalone = verifyStandalone;
exports.verifyById = verifyById;
exports.verifyByIdSync = verifyByIdSync;
exports.reencryptKey = reencryptKey;
exports.reencryptKeySync = reencryptKeySync;
exports.getPublicKey = getPublicKey;
exports.exportAgent = exportAgent;
exports.getAgentInfo = getAgentInfo;
exports.isLoaded = isLoaded;
exports.debugInfo = debugInfo;
exports.reset = reset;
exports.getDnsRecord = getDnsRecord;
exports.getWellKnownJson = getWellKnownJson;
exports.getSetupInstructions = getSetupInstructions;
exports.getSetupInstructionsSync = getSetupInstructionsSync;
exports.registerWithHai = registerWithHai;
exports.createAgreement = createAgreement;
exports.createAgreementSync = createAgreementSync;
exports.signAgreement = signAgreement;
exports.signAgreementSync = signAgreementSync;
exports.checkAgreement = checkAgreement;
exports.checkAgreementSync = checkAgreementSync;
exports.trustAgent = trustAgent;
exports.listTrustedAgents = listTrustedAgents;
exports.untrustAgent = untrustAgent;
exports.isTrusted = isTrusted;
exports.getTrustedAgent = getTrustedAgent;
exports.audit = audit;
exports.auditSync = auditSync;
exports.generateVerifyLink = generateVerifyLink;
const index_1 = require("./index");
Object.defineProperty(exports, "JacsAgent", { enumerable: true, get: function () { return index_1.JacsAgent; } });
Object.defineProperty(exports, "hashString", { enumerable: true, get: function () { return index_1.hashString; } });
Object.defineProperty(exports, "createConfig", { enumerable: true, get: function () { return index_1.createConfig; } });
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// =============================================================================
// Global State
// =============================================================================
let globalAgent = null;
let agentInfo = null;
let strictMode = false;
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
function resolveConfigRelativePath(configPath, candidate) {
    if (path.isAbsolute(candidate)) {
        return candidate;
    }
    return path.resolve(path.dirname(configPath), candidate);
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
function extractAgentInfo(resolvedConfigPath) {
    const config = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8'));
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const [agentId] = agentIdVersion.split(':');
    const keyDir = resolveConfigRelativePath(resolvedConfigPath, config.jacs_key_directory || './jacs_keys');
    return {
        agentId: agentId || '',
        name: config.name || '',
        publicKeyPath: path.join(keyDir, 'jacs.public.pem'),
        configPath: resolvedConfigPath,
    };
}
function parseCreateResult(resultJson, options) {
    const info = JSON.parse(resultJson);
    return {
        agentId: info.agent_id || '',
        name: info.name || options.name,
        publicKeyPath: info.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
        configPath: info.config_path || options.configPath || './jacs.config.json',
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
        throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
    }
    return globalAgent;
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
    const extractAttachments = () => (doc.jacsFiles || []).map((f) => ({
        filename: f.path || '',
        mimeType: f.mimetype || 'application/octet-stream',
        hash: f.sha256 || '',
        embedded: f.embed || false,
        content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
    }));
    const makeSuccess = () => ({
        valid: true,
        data: doc.content,
        signerId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
        attachments: extractAttachments(),
        errors: [],
    });
    const makeFailure = (e) => {
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
        }
        catch (e) {
            return makeFailure(e);
        }
    }
    else {
        return agent.verifyDocument(signedDocument)
            .then(() => makeSuccess())
            .catch((e) => makeFailure(e));
    }
}
function ensurePassword() {
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
async function quickstart(options) {
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
function quickstartSync(options) {
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
function resolveCreatePassword(options) {
    const p = options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
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
    const resultJson = await (0, index_1.createAgent)(...createNativeArgs(options, password));
    return parseCreateResult(resultJson, options);
}
/**
 * Creates a new JACS agent (sync, blocks event loop).
 */
function createSync(options) {
    const password = resolveCreatePassword(options);
    const resultJson = (0, index_1.createAgentSync)(...createNativeArgs(options, password));
    return parseCreateResult(resultJson, options);
}
/**
 * Loads an existing agent from a configuration file.
 */
async function load(configPath, options) {
    strictMode = resolveStrict(options?.strict);
    const requestedPath = configPath || './jacs.config.json';
    const resolvedConfigPath = path.resolve(requestedPath);
    if (!fs.existsSync(resolvedConfigPath)) {
        throw new Error(`Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`);
    }
    globalAgent = new index_1.JacsAgent();
    await globalAgent.load(resolvedConfigPath);
    agentInfo = extractAgentInfo(resolvedConfigPath);
    return agentInfo;
}
/**
 * Loads an existing agent (sync, blocks event loop).
 */
function loadSync(configPath, options) {
    strictMode = resolveStrict(options?.strict);
    const requestedPath = configPath || './jacs.config.json';
    const resolvedConfigPath = path.resolve(requestedPath);
    if (!fs.existsSync(resolvedConfigPath)) {
        throw new Error(`Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`);
    }
    globalAgent = new index_1.JacsAgent();
    globalAgent.loadSync(resolvedConfigPath);
    agentInfo = extractAgentInfo(resolvedConfigPath);
    return agentInfo;
}
/**
 * Verifies the currently loaded agent's integrity.
 */
async function verifySelf() {
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
    }
    catch (e) {
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
function verifySelfSync() {
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
    }
    catch (e) {
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
async function signMessage(data) {
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
function signMessageSync(data) {
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
async function updateAgent(newAgentData) {
    const agent = requireAgent();
    const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return agent.updateAgent(dataString);
}
/**
 * Updates the agent document (sync, blocks event loop).
 */
function updateAgentSync(newAgentData) {
    const agent = requireAgent();
    const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
    return agent.updateAgentSync(dataString);
}
/**
 * Updates an existing document with new data and re-signs it.
 */
async function updateDocument(documentId, newDocumentData, attachments, embed) {
    const agent = requireAgent();
    const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
    const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
    return parseSignedResult(result);
}
/**
 * Updates an existing document (sync, blocks event loop).
 */
function updateDocumentSync(documentId, newDocumentData, attachments, embed) {
    const agent = requireAgent();
    const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
    const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
    return parseSignedResult(result);
}
/**
 * Signs a file with optional content embedding.
 */
async function signFile(filePath, embed = false) {
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
function signFileSync(filePath, embed = false) {
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
async function verifyById(documentId) {
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
    }
    catch (e) {
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
function verifyByIdSync(documentId) {
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
    }
    catch (e) {
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
// Pure sync helpers (no NAPI calls, stay sync-only)
// =============================================================================
function getPublicKey() {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
    }
    if (!fs.existsSync(agentInfo.publicKeyPath)) {
        throw new Error(`Public key not found: ${agentInfo.publicKeyPath}`);
    }
    return fs.readFileSync(agentInfo.publicKeyPath, 'utf8');
}
function exportAgent() {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
    }
    const configPath = path.resolve(agentInfo.configPath);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const dataDir = resolveConfigRelativePath(configPath, config.jacs_data_directory || './jacs_data');
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const agentPath = path.join(dataDir, 'agent', `${agentIdVersion}.json`);
    if (!fs.existsSync(agentPath)) {
        throw new Error(`Agent file not found: ${agentPath}`);
    }
    return fs.readFileSync(agentPath, 'utf8');
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
    globalAgent = null;
    agentInfo = null;
    strictMode = false;
}
function getDnsRecord(domain, ttl = 3600) {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
    }
    const agentDoc = JSON.parse(exportAgent());
    const jacsId = agentDoc.jacsId || agentDoc.agentId || '';
    const publicKeyHash = agentDoc.jacsSignature?.publicKeyHash ||
        agentDoc.jacsSignature?.['publicKeyHash'] ||
        '';
    const d = domain.replace(/\.$/, '');
    const owner = `_v1.agent.jacs.${d}.`;
    const txt = `v=hai.ai; jacs_agent_id=${jacsId}; alg=SHA-256; enc=base64; jac_public_key_hash=${publicKeyHash}`;
    return `${owner} ${ttl} IN TXT "${txt}"`;
}
function getWellKnownJson() {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call quickstart() for zero-config setup, or load() for a persistent agent.');
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
// =============================================================================
// HAI Registration
// =============================================================================
async function registerWithHai(options) {
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
    const data = (await res.json());
    const signatures = (data.signatures ?? []).map((s) => (typeof s === 'string' ? s : s.signature ?? s.key_id ?? ''));
    return {
        agentId: data.agent_id ?? '',
        jacsId: data.jacs_id ?? '',
        dnsVerified: data.dns_verified ?? false,
        signatures,
    };
}
async function createAgreement(document, agentIds, question, context, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = await agent.createAgreement(docString, agentIds, question || null, context || null, fieldName || null);
    return parseSignedResult(result);
}
function createAgreementSync(document, agentIds, question, context, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = agent.createAgreementSync(docString, agentIds, question || null, context || null, fieldName || null);
    return parseSignedResult(result);
}
async function signAgreement(document, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = await agent.signAgreement(docString, fieldName || null);
    return parseSignedResult(result);
}
function signAgreementSync(document, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = agent.signAgreementSync(docString, fieldName || null);
    return parseSignedResult(result);
}
async function checkAgreement(document, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = await agent.checkAgreement(docString, fieldName || null);
    return JSON.parse(result);
}
function checkAgreementSync(document, fieldName) {
    const agent = requireAgent();
    const docString = normalizeDocumentInput(document);
    const result = agent.checkAgreementSync(docString, fieldName || null);
    return JSON.parse(result);
}
// =============================================================================
// Trust Store Functions (sync-only — fast local file lookups)
// =============================================================================
function trustAgent(agentJson) {
    return (0, index_1.trustAgent)(agentJson);
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
// Verify link
// =============================================================================
exports.MAX_VERIFY_URL_LEN = 2048;
exports.MAX_VERIFY_DOCUMENT_BYTES = 1515;
function generateVerifyLink(document, baseUrl = 'https://hai.ai') {
    const base = baseUrl.replace(/\/+$/, '');
    const encoded = Buffer.from(document, 'utf8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
    const fullUrl = `${base}/jacs/verify?s=${encoded}`;
    if (fullUrl.length > exports.MAX_VERIFY_URL_LEN) {
        throw new Error(`Verify URL would exceed max length (${exports.MAX_VERIFY_URL_LEN}). Document size must be at most ${exports.MAX_VERIFY_DOCUMENT_BYTES} UTF-8 bytes.`);
    }
    return fullUrl;
}
//# sourceMappingURL=simple.js.map