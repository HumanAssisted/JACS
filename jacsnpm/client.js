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
function normalizeA2AVerificationResult(rawVerificationResult) {
    if (typeof rawVerificationResult === 'boolean') {
        return {
            valid: rawVerificationResult,
            verificationResult: rawVerificationResult,
        };
    }
    if (rawVerificationResult && typeof rawVerificationResult === 'object') {
        const rawObj = rawVerificationResult;
        const payload = rawObj.payload;
        return {
            valid: true,
            verifiedPayload: payload && typeof payload === 'object'
                ? payload
                : undefined,
            verificationResult: rawObj,
        };
    }
    return {
        valid: false,
        verificationResult: false,
    };
}
function extractAgentInfo(resolvedConfigPath) {
    const config = JSON.parse(fs.readFileSync(resolvedConfigPath, 'utf8'));
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const [agentId, version] = agentIdVersion.split(':');
    const dataDir = resolveConfigRelativePath(resolvedConfigPath, config.jacs_data_directory || './jacs_data');
    const keyDir = resolveConfigRelativePath(resolvedConfigPath, config.jacs_key_directory || './jacs_keys');
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
function requireQuickstartIdentity(options) {
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
function parseSignedResult(result) {
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
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
        const persistPassword = process.env.JACS_SAVE_PASSWORD_FILE === '1' ||
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
     * Factory: loads or creates a persistent agent.
     */
    static async quickstart(options) {
        const { name, domain, description } = requireQuickstartIdentity(options);
        const client = new JacsClient({ strict: options?.strict });
        const configPath = options?.configPath || './jacs.config.json';
        if (fs.existsSync(configPath)) {
            await client.load(configPath);
            return client;
        }
        const password = ensurePassword();
        const algo = options?.algorithm || 'pq2025';
        await client.create({ name, password, algorithm: algo, configPath, domain, description });
        return client;
    }
    /**
     * Factory (sync variant).
     */
    static quickstartSync(options) {
        const { name, domain, description } = requireQuickstartIdentity(options);
        const client = new JacsClient({ strict: options?.strict });
        const configPath = options?.configPath || './jacs.config.json';
        if (fs.existsSync(configPath)) {
            client.loadSync(configPath);
            return client;
        }
        const password = ensurePassword();
        const algo = options?.algorithm || 'pq2025';
        client.createSync({ name, password, algorithm: algo, configPath, domain, description });
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
        const dataDirectory = result.data_directory || options.dataDirectory || './jacs_data';
        const keyDirectory = result.key_directory || options.keyDirectory || './jacs_keys';
        const publicKeyPath = result.public_key_path || `${keyDirectory}/jacs.public.pem`;
        const privateKeyPath = result.private_key_path || `${keyDirectory}/jacs.private.pem.enc`;
        this.info = {
            agentId: result.agent_id || '',
            name: result.name || options.name,
            publicKeyPath,
            configPath: cfgPath,
            version: result.version || '',
            algorithm: result.algorithm || options.algorithm || 'pq2025',
            privateKeyPath,
            dataDirectory,
            keyDirectory,
            domain: result.domain || options.domain || '',
            dnsRecord: result.dns_record || '',
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
        const dataDirectory = result.data_directory || options.dataDirectory || './jacs_data';
        const keyDirectory = result.key_directory || options.keyDirectory || './jacs_keys';
        const publicKeyPath = result.public_key_path || `${keyDirectory}/jacs.public.pem`;
        const privateKeyPath = result.private_key_path || `${keyDirectory}/jacs.private.pem.enc`;
        this.info = {
            agentId: result.agent_id || '',
            name: result.name || options.name,
            publicKeyPath,
            configPath: cfgPath,
            version: result.version || '',
            algorithm: result.algorithm || options.algorithm || 'pq2025',
            privateKeyPath,
            dataDirectory,
            keyDirectory,
            domain: result.domain || options.domain || '',
            dnsRecord: result.dns_record || '',
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
    readStoredDocumentById(documentId) {
        if (!this.info) {
            return null;
        }
        try {
            const configPath = path.resolve(this.info.configPath);
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            const dataDir = resolveConfigRelativePath(configPath, config.jacs_data_directory || './jacs_data');
            const docPath = path.join(dataDir, 'documents', `${documentId}.json`);
            if (!fs.existsSync(docPath)) {
                return null;
            }
            return JSON.parse(fs.readFileSync(docPath, 'utf8'));
        }
        catch {
            return null;
        }
    }
    /**
     * Internal access to the native JacsAgent for A2A and other low-level integrations.
     * @internal
     */
    get _agent() {
        return this.requireAgent();
    }
    // ---------------------------------------------------------------------------
    // Signing & Verification
    // ---------------------------------------------------------------------------
    requireAgent() {
        if (!this.agent) {
            throw new Error('No agent loaded. Call quickstart({ name, domain }), ephemeral(), load(), or create() first.');
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
            const attachments = extractAttachmentsFromDocument(doc);
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
            const attachments = extractAttachmentsFromDocument(doc);
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
            const stored = this.readStoredDocumentById(documentId);
            return {
                valid: true,
                signerId: stored?.jacsSignature?.agentID || '',
                timestamp: stored?.jacsSignature?.date || '',
                attachments: extractAttachmentsFromDocument(stored || {}),
                errors: [],
            };
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
            const stored = this.readStoredDocumentById(documentId);
            return {
                valid: true,
                signerId: stored?.jacsSignature?.agentID || '',
                timestamp: stored?.jacsSignature?.date || '',
                attachments: extractAttachmentsFromDocument(stored || {}),
                errors: [],
            };
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
    trustAgentWithKey(agentJson, publicKeyPem) {
        if (!publicKeyPem || !publicKeyPem.trim()) {
            throw new Error('publicKeyPem cannot be empty');
        }
        return (0, index_1.trustAgentWithKey)(agentJson, publicKeyPem);
    }
    listTrustedAgents() { return (0, index_1.listTrustedAgents)(); }
    untrustAgent(agentId) { (0, index_1.untrustAgent)(agentId); }
    isTrusted(agentId) { return (0, index_1.isTrusted)(agentId); }
    getTrustedAgent(agentId) { return (0, index_1.getTrustedAgent)(agentId); }
    getPublicKey() {
        if (!this.info) {
            throw new Error('No agent loaded. Call quickstart({ name, domain }), ephemeral(), load(), or create() first.');
        }
        const keyPath = this.info.publicKeyPath;
        if (!keyPath || !fs.existsSync(keyPath)) {
            throw new Error(`Public key not found: ${keyPath}`);
        }
        return fs.readFileSync(keyPath, 'utf8');
    }
    exportAgent() {
        if (!this.info) {
            throw new Error('No agent loaded. Call quickstart({ name, domain }), ephemeral(), load(), or create() first.');
        }
        const configPath = path.resolve(this.info.configPath);
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        const dataDir = resolveConfigRelativePath(configPath, config.jacs_data_directory || './jacs_data');
        const agentIdVersion = config.jacs_agent_id_and_version || '';
        const agentPath = path.join(dataDir, 'agent', `${agentIdVersion}.json`);
        if (!fs.existsSync(agentPath)) {
            throw new Error(`Agent file not found: ${agentPath}`);
        }
        return fs.readFileSync(agentPath, 'utf8');
    }
    sharePublicKey() {
        return this.getPublicKey();
    }
    shareAgent() {
        return this.exportAgent();
    }
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
    // ---------------------------------------------------------------------------
    // Attestation
    // ---------------------------------------------------------------------------
    /**
     * Create a signed attestation document.
     *
     * @param params - Object with subject, claims, and optional evidence/derivation/policyContext.
     * @returns The signed attestation document as a SignedDocument.
     */
    async createAttestation(params) {
        const agent = this.requireAgent();
        const paramsJson = JSON.stringify(params);
        const raw = await agent.createAttestation(paramsJson);
        return parseSignedResult(raw);
    }
    /**
     * Verify an attestation document.
     *
     * @param attestationJson - Raw JSON string of the attestation document.
     * @param opts - Optional. Set full: true for full-tier verification.
     * @returns Verification result with valid, crypto, evidence, chain, errors.
     */
    async verifyAttestation(attestationJson, opts) {
        const agent = this.requireAgent();
        const doc = JSON.parse(attestationJson);
        const docKey = `${doc.jacsId}:${doc.jacsVersion}`;
        let resultJson;
        if (opts?.full) {
            resultJson = await agent.verifyAttestationFull(docKey);
        }
        else {
            resultJson = await agent.verifyAttestation(docKey);
        }
        return JSON.parse(resultJson);
    }
    /**
     * Lift a signed document into an attestation.
     *
     * @param signedDocJson - Raw JSON string of the signed document.
     * @param claims - Array of claim objects.
     * @returns The lifted attestation as a SignedDocument.
     */
    async liftToAttestation(signedDocJson, claims) {
        const agent = this.requireAgent();
        const claimsJson = JSON.stringify(claims);
        const raw = await agent.liftToAttestation(signedDocJson, claimsJson);
        return parseSignedResult(raw);
    }
    /**
     * Export an attestation as a DSSE (Dead Simple Signing Envelope).
     *
     * @param attestationJson - Raw JSON string of the attestation document.
     * @returns The DSSE envelope as a parsed object.
     */
    async exportAttestationDsse(attestationJson) {
        const agent = this.requireAgent();
        const raw = await agent.exportAttestationDsse(attestationJson);
        return JSON.parse(raw);
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
    getA2A() {
        const { JACSA2AIntegration } = require('./a2a');
        return new JACSA2AIntegration(this);
    }
    /**
     * Export this agent as an A2A Agent Card.
     *
     * @param agentData - JACS agent data (jacsId, jacsName, jacsServices, etc.).
     *   If not provided, a minimal card is built from the client's own info.
     */
    exportAgentCard(agentData) {
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
    async signArtifact(artifact, artifactType, parentSignatures) {
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
    async verifyArtifact(wrappedArtifact) {
        const agent = this.requireAgent();
        const docString = typeof wrappedArtifact === 'string'
            ? wrappedArtifact
            : JSON.stringify(wrappedArtifact);
        const doc = typeof wrappedArtifact === 'string'
            ? JSON.parse(wrappedArtifact)
            : wrappedArtifact;
        const payload = doc.jacs_payload && typeof doc.jacs_payload === 'object'
            ? doc.jacs_payload
            : null;
        try {
            const rawVerificationResult = agent.verifyResponse(docString);
            const normalized = normalizeA2AVerificationResult(rawVerificationResult);
            const sig = doc.jacsSignature || {};
            const result = {
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
        }
        catch (e) {
            if (this._strict)
                throw new Error(`Artifact verification failed (strict mode): ${e}`);
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
    generateWellKnownDocuments(agentCard, jwsSignature, publicKeyB64, agentData) {
        const a2a = this.getA2A();
        return a2a.generateWellKnownDocuments(agentCard, jwsSignature, publicKeyB64, agentData);
    }
}
exports.JacsClient = JacsClient;
//# sourceMappingURL=client.js.map