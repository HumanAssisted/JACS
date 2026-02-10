"use strict";
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
exports.JacsClient = exports.createConfig = exports.hashString = void 0;
const index_1 = require("./index");
Object.defineProperty(exports, "hashString", { enumerable: true, get: function () { return index_1.hashString; } });
Object.defineProperty(exports, "createConfig", { enumerable: true, get: function () { return index_1.createConfig; } });
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// =============================================================================
// Helpers
// =============================================================================
function resolveStrict(explicit) {
    if (explicit !== undefined) {
        return explicit;
    }
    const envStrict = process.env.JACS_STRICT_MODE;
    return envStrict === 'true' || envStrict === '1';
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
function parseSignedResult(result) {
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
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
// =============================================================================
// JacsClient
// =============================================================================
class JacsClient {
    constructor(options) {
        this.agent = null;
        this.info = null;
        this._strict = false;
        this._strict = resolveStrict(options?.strict);
    }
    // ---------------------------------------------------------------------------
    // Static factories (async)
    // ---------------------------------------------------------------------------
    /**
     * Zero-config factory: loads or creates a persistent agent.
     */
    static async quickstart(options) {
        const client = new JacsClient({ strict: options?.strict });
        const configPath = options?.configPath || './jacs.config.json';
        if (fs.existsSync(configPath)) {
            await client.load(configPath);
            return client;
        }
        const password = ensurePassword();
        const algo = options?.algorithm || 'pq2025';
        await client.create({ name: 'jacs-agent', password, algorithm: algo });
        return client;
    }
    /**
     * Zero-config factory (sync variant).
     */
    static quickstartSync(options) {
        const client = new JacsClient({ strict: options?.strict });
        const configPath = options?.configPath || './jacs.config.json';
        if (fs.existsSync(configPath)) {
            client.loadSync(configPath);
            return client;
        }
        const password = ensurePassword();
        const algo = options?.algorithm || 'pq2025';
        client.createSync({ name: 'jacs-agent', password, algorithm: algo });
        return client;
    }
    /**
     * Create an ephemeral in-memory client for testing.
     */
    static async ephemeral(algorithm) {
        const client = new JacsClient();
        const nativeAgent = new index_1.JacsAgent();
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
    static ephemeralSync(algorithm) {
        const client = new JacsClient();
        const nativeAgent = new index_1.JacsAgent();
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
    async load(configPath, options) {
        if (options?.strict !== undefined) {
            this._strict = options.strict;
        }
        const requestedPath = configPath || './jacs.config.json';
        const resolvedConfigPath = path.resolve(requestedPath);
        if (!fs.existsSync(resolvedConfigPath)) {
            throw new Error(`Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`);
        }
        this.agent = new index_1.JacsAgent();
        await this.agent.load(resolvedConfigPath);
        this.info = extractAgentInfo(resolvedConfigPath);
        return this.info;
    }
    loadSync(configPath, options) {
        if (options?.strict !== undefined) {
            this._strict = options.strict;
        }
        const requestedPath = configPath || './jacs.config.json';
        const resolvedConfigPath = path.resolve(requestedPath);
        if (!fs.existsSync(resolvedConfigPath)) {
            throw new Error(`Config file not found: ${requestedPath}\nRun 'jacs create' to create a new agent.`);
        }
        this.agent = new index_1.JacsAgent();
        this.agent.loadSync(resolvedConfigPath);
        this.info = extractAgentInfo(resolvedConfigPath);
        return this.info;
    }
    async create(options) {
        const resolvedPassword = options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
        if (!resolvedPassword) {
            throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
        }
        const resultJson = await (0, index_1.createAgent)(options.name, resolvedPassword, options.algorithm ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null, options.configPath ?? null, options.agentType ?? null, options.description ?? null, options.domain ?? null, options.defaultStorage ?? null);
        const result = JSON.parse(resultJson);
        const cfgPath = result.config_path || options.configPath || './jacs.config.json';
        this.info = {
            agentId: result.agent_id || '',
            name: result.name || options.name,
            publicKeyPath: result.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
            configPath: cfgPath,
        };
        this.agent = new index_1.JacsAgent();
        await this.agent.load(path.resolve(cfgPath));
        return this.info;
    }
    createSync(options) {
        const resolvedPassword = options.password ?? process.env.JACS_PRIVATE_KEY_PASSWORD ?? '';
        if (!resolvedPassword) {
            throw new Error('Missing private key password. Pass options.password or set JACS_PRIVATE_KEY_PASSWORD.');
        }
        const resultJson = (0, index_1.createAgentSync)(options.name, resolvedPassword, options.algorithm ?? null, options.dataDirectory ?? null, options.keyDirectory ?? null, options.configPath ?? null, options.agentType ?? null, options.description ?? null, options.domain ?? null, options.defaultStorage ?? null);
        const result = JSON.parse(resultJson);
        const cfgPath = result.config_path || options.configPath || './jacs.config.json';
        this.info = {
            agentId: result.agent_id || '',
            name: result.name || options.name,
            publicKeyPath: result.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
            configPath: cfgPath,
        };
        this.agent = new index_1.JacsAgent();
        this.agent.loadSync(path.resolve(cfgPath));
        return this.info;
    }
    reset() {
        this.agent = null;
        this.info = null;
        this._strict = false;
    }
    dispose() {
        this.reset();
    }
    [Symbol.dispose]() {
        this.reset();
    }
    // ---------------------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------------------
    get agentId() {
        return this.info?.agentId || '';
    }
    get name() {
        return this.info?.name || '';
    }
    get strict() {
        return this._strict;
    }
    // ---------------------------------------------------------------------------
    // Signing & Verification
    // ---------------------------------------------------------------------------
    requireAgent() {
        if (!this.agent) {
            throw new Error('No agent loaded. Call quickstart(), ephemeral(), load(), or create() first.');
        }
        return this.agent;
    }
    async signMessage(data) {
        const agent = this.requireAgent();
        const docContent = { jacsType: 'message', jacsLevel: 'raw', content: data };
        const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, null, null);
        return parseSignedResult(result);
    }
    signMessageSync(data) {
        const agent = this.requireAgent();
        const docContent = { jacsType: 'message', jacsLevel: 'raw', content: data };
        const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, null, null);
        return parseSignedResult(result);
    }
    async verify(signedDocument) {
        const agent = this.requireAgent();
        const trimmed = signedDocument.trim();
        if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Input does not appear to be a JSON document. If you have a document ID (e.g., 'uuid:version'), use verifyById() instead. Received: '${trimmed.substring(0, 50)}${trimmed.length > 50 ? '...' : ''}'`] };
        }
        let doc;
        try {
            doc = JSON.parse(signedDocument);
        }
        catch (e) {
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Invalid JSON: ${e}`] };
        }
        try {
            await agent.verifyDocument(signedDocument);
            const attachments = (doc.jacsFiles || []).map((f) => ({
                filename: f.path || '', mimeType: f.mimetype || 'application/octet-stream',
                hash: f.sha256 || '', embedded: f.embed || false,
                content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
            }));
            return { valid: true, data: doc.content, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments, errors: [] };
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Verification failed (strict mode): ${e}`);
            return { valid: false, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments: [], errors: [String(e)] };
        }
    }
    verifySync(signedDocument) {
        const agent = this.requireAgent();
        const trimmed = signedDocument.trim();
        if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Input does not appear to be a JSON document.`] };
        }
        let doc;
        try {
            doc = JSON.parse(signedDocument);
        }
        catch (e) {
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Invalid JSON: ${e}`] };
        }
        try {
            agent.verifyDocumentSync(signedDocument);
            const attachments = (doc.jacsFiles || []).map((f) => ({
                filename: f.path || '', mimeType: f.mimetype || 'application/octet-stream',
                hash: f.sha256 || '', embedded: f.embed || false,
                content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
            }));
            return { valid: true, data: doc.content, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments, errors: [] };
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Verification failed (strict mode): ${e}`);
            return { valid: false, signerId: doc.jacsSignature?.agentID || '', timestamp: doc.jacsSignature?.date || '', attachments: [], errors: [String(e)] };
        }
    }
    async verifySelf() {
        const agent = this.requireAgent();
        try {
            await agent.verifyAgent();
            return { valid: true, signerId: this.info?.agentId || '', timestamp: '', attachments: [], errors: [] };
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Self-verification failed (strict mode): ${e}`);
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
        }
    }
    verifySelfSync() {
        const agent = this.requireAgent();
        try {
            agent.verifyAgentSync();
            return { valid: true, signerId: this.info?.agentId || '', timestamp: '', attachments: [], errors: [] };
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Self-verification failed (strict mode): ${e}`);
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
        }
    }
    async verifyById(documentId) {
        const agent = this.requireAgent();
        if (!documentId.includes(':')) {
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Document ID must be in 'uuid:version' format, got '${documentId}'.`] };
        }
        try {
            await agent.verifyDocumentById(documentId);
            return { valid: true, signerId: '', timestamp: '', attachments: [], errors: [] };
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Verification failed (strict mode): ${e}`);
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
        }
    }
    verifyByIdSync(documentId) {
        const agent = this.requireAgent();
        if (!documentId.includes(':')) {
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [`Document ID must be in 'uuid:version' format, got '${documentId}'.`] };
        }
        try {
            agent.verifyDocumentByIdSync(documentId);
            return { valid: true, signerId: '', timestamp: '', attachments: [], errors: [] };
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Verification failed (strict mode): ${e}`);
            return { valid: false, signerId: '', timestamp: '', attachments: [], errors: [String(e)] };
        }
    }
    // ---------------------------------------------------------------------------
    // Files
    // ---------------------------------------------------------------------------
    async signFile(filePath, embed = false) {
        const agent = this.requireAgent();
        if (!fs.existsSync(filePath))
            throw new Error(`File not found: ${filePath}`);
        const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
        const result = await agent.createDocument(JSON.stringify(docContent), null, null, true, filePath, embed);
        return parseSignedResult(result);
    }
    signFileSync(filePath, embed = false) {
        const agent = this.requireAgent();
        if (!fs.existsSync(filePath))
            throw new Error(`File not found: ${filePath}`);
        const docContent = { jacsType: 'file', jacsLevel: 'raw', filename: path.basename(filePath) };
        const result = agent.createDocumentSync(JSON.stringify(docContent), null, null, true, filePath, embed);
        return parseSignedResult(result);
    }
    // ---------------------------------------------------------------------------
    // Agreements
    // ---------------------------------------------------------------------------
    async createAgreement(document, agentIds, options) {
        const agent = this.requireAgent();
        const docString = normalizeDocumentInput(document);
        const hasExtended = options?.timeout || options?.quorum !== undefined || options?.requiredAlgorithms || options?.minimumStrength;
        let result;
        if (hasExtended) {
            result = await agent.createAgreementWithOptions(docString, agentIds, options?.question || null, options?.context || null, options?.fieldName || null, options?.timeout || null, options?.quorum ?? null, options?.requiredAlgorithms || null, options?.minimumStrength || null);
        }
        else {
            result = await agent.createAgreement(docString, agentIds, options?.question || null, options?.context || null, options?.fieldName || null);
        }
        return parseSignedResult(result);
    }
    createAgreementSync(document, agentIds, options) {
        const agent = this.requireAgent();
        const docString = normalizeDocumentInput(document);
        const hasExtended = options?.timeout || options?.quorum !== undefined || options?.requiredAlgorithms || options?.minimumStrength;
        let result;
        if (hasExtended) {
            result = agent.createAgreementWithOptionsSync(docString, agentIds, options?.question || null, options?.context || null, options?.fieldName || null, options?.timeout || null, options?.quorum ?? null, options?.requiredAlgorithms || null, options?.minimumStrength || null);
        }
        else {
            result = agent.createAgreementSync(docString, agentIds, options?.question || null, options?.context || null, options?.fieldName || null);
        }
        return parseSignedResult(result);
    }
    async signAgreement(document, fieldName) {
        const agent = this.requireAgent();
        const docString = normalizeDocumentInput(document);
        const result = await agent.signAgreement(docString, fieldName || null);
        return parseSignedResult(result);
    }
    signAgreementSync(document, fieldName) {
        const agent = this.requireAgent();
        const docString = normalizeDocumentInput(document);
        const result = agent.signAgreementSync(docString, fieldName || null);
        return parseSignedResult(result);
    }
    async checkAgreement(document, fieldName) {
        const agent = this.requireAgent();
        const docString = normalizeDocumentInput(document);
        const result = await agent.checkAgreement(docString, fieldName || null);
        return JSON.parse(result);
    }
    checkAgreementSync(document, fieldName) {
        const agent = this.requireAgent();
        const docString = normalizeDocumentInput(document);
        const result = agent.checkAgreementSync(docString, fieldName || null);
        return JSON.parse(result);
    }
    // ---------------------------------------------------------------------------
    // Agent management
    // ---------------------------------------------------------------------------
    async updateAgent(newAgentData) {
        const agent = this.requireAgent();
        const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
        return agent.updateAgent(dataString);
    }
    updateAgentSync(newAgentData) {
        const agent = this.requireAgent();
        const dataString = typeof newAgentData === 'string' ? newAgentData : JSON.stringify(newAgentData);
        return agent.updateAgentSync(dataString);
    }
    async updateDocument(documentId, newDocumentData, attachments, embed) {
        const agent = this.requireAgent();
        const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
        const result = await agent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
        return parseSignedResult(result);
    }
    updateDocumentSync(documentId, newDocumentData, attachments, embed) {
        const agent = this.requireAgent();
        const dataString = typeof newDocumentData === 'string' ? newDocumentData : JSON.stringify(newDocumentData);
        const result = agent.updateDocumentSync(documentId, dataString, attachments || null, embed ?? null);
        return parseSignedResult(result);
    }
    // ---------------------------------------------------------------------------
    // Trust Store (sync-only)
    // ---------------------------------------------------------------------------
    trustAgent(agentJson) { return (0, index_1.trustAgent)(agentJson); }
    listTrustedAgents() { return (0, index_1.listTrustedAgents)(); }
    untrustAgent(agentId) { (0, index_1.untrustAgent)(agentId); }
    isTrusted(agentId) { return (0, index_1.isTrusted)(agentId); }
    getTrustedAgent(agentId) { return (0, index_1.getTrustedAgent)(agentId); }
    // ---------------------------------------------------------------------------
    // Audit
    // ---------------------------------------------------------------------------
    async audit(options) {
        const json = await (0, index_1.audit)(options?.configPath ?? undefined, options?.recentN ?? undefined);
        return JSON.parse(json);
    }
    auditSync(options) {
        const json = (0, index_1.auditSync)(options?.configPath ?? undefined, options?.recentN ?? undefined);
        return JSON.parse(json);
    }
}
exports.JacsClient = JacsClient;
//# sourceMappingURL=client.js.map