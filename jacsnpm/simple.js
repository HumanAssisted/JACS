"use strict";
/**
 * JACS Simplified API for TypeScript/JavaScript
 *
 * A streamlined interface for the most common JACS operations:
 * - load(): Load an existing agent from config
 * - verifySelf(): Verify the loaded agent's integrity
 * - signMessage(): Sign a message or data
 * - verify(): Verify any signed document
 * - signFile(): Sign a file with optional embedding
 * - updateAgent(): Update the agent document with new data
 * - updateDocument(): Update an existing document with new data
 * - createAgreement(): Create a multi-party agreement
 * - signAgreement(): Sign an existing agreement
 * - checkAgreement(): Check agreement status
 *
 * Also re-exports for advanced usage:
 * - JacsAgent: Class for direct agent control
 * - hashString: Standalone SHA-256 hashing
 * - verifyString: Verify with external public key
 * - createConfig: Create agent configuration
 *
 * @example
 * ```typescript
 * import * as jacs from '@hai-ai/jacs/simple';
 *
 * // Load agent
 * const agent = jacs.load('./jacs.config.json');
 *
 * // Sign a message
 * const signed = jacs.signMessage({ action: 'approve', amount: 100 });
 *
 * // Verify it
 * const result = jacs.verify(signed.raw);
 * console.log(`Valid: ${result.valid}`);
 *
 * // Use standalone hash function
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
exports.createConfig = exports.verifyString = exports.hashString = exports.JacsAgent = void 0;
exports.create = create;
exports.load = load;
exports.verifySelf = verifySelf;
exports.signMessage = signMessage;
exports.updateAgent = updateAgent;
exports.updateDocument = updateDocument;
exports.signFile = signFile;
exports.verify = verify;
exports.getPublicKey = getPublicKey;
exports.exportAgent = exportAgent;
exports.getAgentInfo = getAgentInfo;
exports.isLoaded = isLoaded;
exports.createAgreement = createAgreement;
exports.signAgreement = signAgreement;
exports.checkAgreement = checkAgreement;
const index_1 = require("./index");
Object.defineProperty(exports, "JacsAgent", { enumerable: true, get: function () { return index_1.JacsAgent; } });
Object.defineProperty(exports, "hashString", { enumerable: true, get: function () { return index_1.hashString; } });
Object.defineProperty(exports, "verifyString", { enumerable: true, get: function () { return index_1.verifyString; } });
Object.defineProperty(exports, "createConfig", { enumerable: true, get: function () { return index_1.createConfig; } });
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// =============================================================================
// Global State
// =============================================================================
let globalAgent = null;
let agentInfo = null;
// =============================================================================
// Core Operations
// =============================================================================
/**
 * Creates a new JACS agent with cryptographic keys.
 *
 * @param name - Human-readable name for the agent
 * @param purpose - Optional description of the agent's purpose
 * @param keyAlgorithm - Signing algorithm: "ed25519" (default), "rsa-pss", or "pq2025"
 * @returns AgentInfo containing the agent ID, name, and file paths
 *
 * @example
 * ```typescript
 * const agent = await jacs.create('my-agent', 'Signing documents');
 * console.log(`Created: ${agent.agentId}`);
 * ```
 */
function create(name, purpose, keyAlgorithm) {
    // This would call the Rust create function when available
    // For now, throw an error directing to CLI
    throw new Error('Agent creation from JS not yet supported. Use CLI: jacs create');
}
/**
 * Loads an existing agent from a configuration file.
 *
 * @param configPath - Path to jacs.config.json (default: "./jacs.config.json")
 * @returns AgentInfo with the loaded agent's details
 *
 * @example
 * ```typescript
 * const agent = jacs.load('./jacs.config.json');
 * console.log(`Loaded: ${agent.agentId}`);
 * ```
 */
function load(configPath) {
    const path = configPath || './jacs.config.json';
    if (!fs.existsSync(path)) {
        throw new Error(`Config file not found: ${path}\nRun 'jacs create' to create a new agent.`);
    }
    // Create new agent instance
    globalAgent = new index_1.JacsAgent();
    globalAgent.load(path);
    // Read config to get agent info
    const config = JSON.parse(fs.readFileSync(path, 'utf8'));
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const [agentId, version] = agentIdVersion.split(':');
    agentInfo = {
        agentId: agentId || '',
        name: config.name || '',
        publicKeyPath: `${config.jacs_key_directory || './jacs_keys'}/jacs.public.pem`,
        configPath: path,
    };
    return agentInfo;
}
/**
 * Verifies the currently loaded agent's integrity.
 *
 * @returns VerificationResult indicating if the agent is valid
 *
 * @example
 * ```typescript
 * const result = jacs.verifySelf();
 * if (result.valid) {
 *   console.log('Agent integrity verified');
 * }
 * ```
 */
function verifySelf() {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    try {
        globalAgent.verifyAgent();
        return {
            valid: true,
            signerId: agentInfo?.agentId || '',
            timestamp: '',
            attachments: [],
            errors: [],
        };
    }
    catch (e) {
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
 *
 * @param data - The data to sign (object, string, or any JSON-serializable value)
 * @returns SignedDocument containing the full signed document
 *
 * @example
 * ```typescript
 * const signed = jacs.signMessage({ action: 'approve', amount: 100 });
 * console.log(`Document ID: ${signed.documentId}`);
 * ```
 */
function signMessage(data) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    // Create document structure
    const docContent = {
        jacsType: 'message',
        jacsLevel: 'raw',
        content: data,
    };
    const result = globalAgent.createDocument(JSON.stringify(docContent), null, null, true, // no_save
    null, null);
    // Parse result
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
}
/**
 * Updates the agent document with new data and re-signs it.
 *
 * This function expects a complete agent document (not partial updates).
 * Use exportAgent() to get the current document, modify it, then pass it here.
 * The function will create a new version, re-sign, and re-hash the document.
 *
 * @param newAgentData - Complete agent document as JSON string or object
 * @returns The updated and re-signed agent document as a JSON string
 *
 * @example
 * ```typescript
 * // Get current agent, modify, and update
 * const agentDoc = JSON.parse(jacs.exportAgent());
 * agentDoc.jacsAgentType = 'updated-service';
 * const updated = jacs.updateAgent(agentDoc);
 * console.log('Agent updated with new version');
 * ```
 */
function updateAgent(newAgentData) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    const dataString = typeof newAgentData === 'string'
        ? newAgentData
        : JSON.stringify(newAgentData);
    return globalAgent.updateAgent(dataString);
}
/**
 * Updates an existing document with new data and re-signs it.
 *
 * Use signMessage() to create a document first, then use this to update it.
 * The function will create a new version, re-sign, and re-hash the document.
 *
 * @param documentId - The document ID (jacsId) to update
 * @param newDocumentData - The updated document as JSON string or object
 * @param attachments - Optional array of file paths to attach
 * @param embed - If true, embed attachment contents
 * @returns SignedDocument with the updated document
 *
 * @example
 * ```typescript
 * // Create a document first
 * const signed = jacs.signMessage({ status: 'pending' });
 *
 * // Later, update it
 * const doc = JSON.parse(signed.raw);
 * doc.content.status = 'approved';
 * const updated = jacs.updateDocument(signed.documentId, doc);
 * console.log('Document updated with new version');
 * ```
 */
function updateDocument(documentId, newDocumentData, attachments, embed) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    const dataString = typeof newDocumentData === 'string'
        ? newDocumentData
        : JSON.stringify(newDocumentData);
    const result = globalAgent.updateDocument(documentId, dataString, attachments || null, embed ?? null);
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
}
/**
 * Signs a file with optional content embedding.
 *
 * @param filePath - Path to the file to sign
 * @param embed - If true, embed file content in the document
 * @returns SignedDocument with file attachment
 *
 * @example
 * ```typescript
 * const signed = jacs.signFile('contract.pdf', true);
 * console.log(`Signed: ${signed.attachments[0].filename}`);
 * ```
 */
function signFile(filePath, embed = false) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }
    // Create document structure
    const docContent = {
        jacsType: 'file',
        jacsLevel: 'raw',
        filename: path.basename(filePath),
    };
    const result = globalAgent.createDocument(JSON.stringify(docContent), null, null, true, // no_save
    filePath, embed);
    // Parse result
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
}
/**
 * Verifies a signed document and extracts its content.
 *
 * @param signedDocument - The JSON string of the signed document
 * @returns VerificationResult with the verification status and extracted content
 *
 * @example
 * ```typescript
 * const result = jacs.verify(signedJson);
 * if (result.valid) {
 *   console.log(`Signed by: ${result.signerId}`);
 * }
 * ```
 */
function verify(signedDocument) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    let doc;
    try {
        doc = JSON.parse(signedDocument);
    }
    catch (e) {
        return {
            valid: false,
            signerId: '',
            timestamp: '',
            attachments: [],
            errors: [`Invalid JSON: ${e}`],
        };
    }
    try {
        globalAgent.verifyDocument(signedDocument);
        // Extract attachments
        const attachments = (doc.jacsFiles || []).map((f) => ({
            filename: f.path || '',
            mimeType: f.mimetype || 'application/octet-stream',
            hash: f.sha256 || '',
            embedded: f.embed || false,
            content: f.contents ? Buffer.from(f.contents, 'base64') : undefined,
        }));
        return {
            valid: true,
            data: doc.content,
            signerId: doc.jacsSignature?.agentID || '',
            timestamp: doc.jacsSignature?.date || '',
            attachments,
            errors: [],
        };
    }
    catch (e) {
        return {
            valid: false,
            signerId: doc.jacsSignature?.agentID || '',
            timestamp: doc.jacsSignature?.date || '',
            attachments: [],
            errors: [String(e)],
        };
    }
}
/**
 * Get the loaded agent's public key in PEM format.
 *
 * @returns The public key as a PEM-encoded string
 *
 * @example
 * ```typescript
 * const pem = jacs.getPublicKey();
 * console.log(pem); // Share with others for verification
 * ```
 */
function getPublicKey() {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call load() first.');
    }
    if (!fs.existsSync(agentInfo.publicKeyPath)) {
        throw new Error(`Public key not found: ${agentInfo.publicKeyPath}`);
    }
    return fs.readFileSync(agentInfo.publicKeyPath, 'utf8');
}
/**
 * Export the agent document for sharing.
 *
 * @returns The agent JSON document as a string
 *
 * @example
 * ```typescript
 * const agentDoc = jacs.exportAgent();
 * // Send to another party for trust establishment
 * ```
 */
function exportAgent() {
    if (!agentInfo) {
        throw new Error('No agent loaded. Call load() first.');
    }
    // Read agent file
    const config = JSON.parse(fs.readFileSync(agentInfo.configPath, 'utf8'));
    const dataDir = config.jacs_data_directory || './jacs_data';
    const agentIdVersion = config.jacs_agent_id_and_version || '';
    const agentPath = path.join(dataDir, 'agent', `${agentIdVersion}.json`);
    if (!fs.existsSync(agentPath)) {
        throw new Error(`Agent file not found: ${agentPath}`);
    }
    return fs.readFileSync(agentPath, 'utf8');
}
/**
 * Get information about the currently loaded agent.
 *
 * @returns AgentInfo if an agent is loaded, null otherwise
 */
function getAgentInfo() {
    return agentInfo;
}
/**
 * Check if an agent is currently loaded.
 *
 * @returns true if an agent is loaded, false otherwise
 */
function isLoaded() {
    return globalAgent !== null;
}
/**
 * Creates a multi-party agreement that requires signatures from multiple agents.
 *
 * @param document - The document to create an agreement on (object or JSON string)
 * @param agentIds - List of agent IDs required to sign
 * @param question - Optional question or purpose of the agreement
 * @param context - Optional additional context for signers
 * @param fieldName - Optional custom field name for the agreement (default: "jacsAgreement")
 * @returns SignedDocument containing the agreement document
 *
 * @example
 * ```typescript
 * const agreement = jacs.createAgreement(
 *   { proposal: 'Merge codebase' },
 *   ['agent-1-uuid', 'agent-2-uuid'],
 *   'Do you approve this merge?',
 *   'This will combine repositories A and B'
 * );
 * ```
 */
function createAgreement(document, agentIds, question, context, fieldName) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    const docString = typeof document === 'string'
        ? document
        : JSON.stringify(document);
    const result = globalAgent.createAgreement(docString, agentIds, question || null, context || null, fieldName || null);
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
}
/**
 * Signs an existing multi-party agreement.
 *
 * @param document - The agreement document to sign (object or JSON string)
 * @param fieldName - Optional custom field name for the agreement (default: "jacsAgreement")
 * @returns SignedDocument with this agent's signature added
 *
 * @example
 * ```typescript
 * // Receive agreement from another party
 * const signedByMe = jacs.signAgreement(agreementDoc);
 * // Send back to coordinator or next signer
 * ```
 */
function signAgreement(document, fieldName) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    const docString = typeof document === 'string'
        ? document
        : JSON.stringify(document);
    const result = globalAgent.signAgreement(docString, fieldName || null);
    const doc = JSON.parse(result);
    return {
        raw: result,
        documentId: doc.jacsId || '',
        agentId: doc.jacsSignature?.agentID || '',
        timestamp: doc.jacsSignature?.date || '',
    };
}
/**
 * Checks the status of a multi-party agreement.
 *
 * @param document - The agreement document to check (object or JSON string)
 * @param fieldName - Optional custom field name for the agreement (default: "jacsAgreement")
 * @returns AgreementStatus with completion status and signer details
 *
 * @example
 * ```typescript
 * const status = jacs.checkAgreement(agreementDoc);
 * if (status.complete) {
 *   console.log('All parties have signed!');
 * } else {
 *   console.log(`Waiting for: ${status.pending.join(', ')}`);
 * }
 * ```
 */
function checkAgreement(document, fieldName) {
    if (!globalAgent) {
        throw new Error('No agent loaded. Call load() first.');
    }
    const docString = typeof document === 'string'
        ? document
        : JSON.stringify(document);
    const result = globalAgent.checkAgreement(docString, fieldName || null);
    return JSON.parse(result);
}
//# sourceMappingURL=simple.js.map