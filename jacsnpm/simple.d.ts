/**
 * JACS Simplified API for TypeScript/JavaScript
 *
 * A streamlined interface for the most common JACS operations:
 * - create(): Create a new agent with keys
 * - load(): Load an existing agent from config
 * - verifySelf(): Verify the loaded agent's integrity
 * - updateAgent(): Update the agent document with new data
 * - updateDocument(): Update an existing document with new data
 * - signMessage(): Sign a text message
 * - signFile(): Sign a file with optional embedding
 * - verify(): Verify any signed document
 *
 * @example
 * ```typescript
 * import * as jacs from '@hai-ai/jacs/simple';
 *
 * // Load agent
 * const agent = await jacs.load('./jacs.config.json');
 *
 * // Sign a message
 * const signed = jacs.signMessage({ action: 'approve', amount: 100 });
 *
 * // Verify it
 * const result = jacs.verify(signed.raw);
 * console.log(`Valid: ${result.valid}`);
 * ```
 */
/// <reference types="node" />
/// <reference types="node" />
/**
 * Information about a created or loaded agent.
 */
export interface AgentInfo {
    /** Unique identifier for the agent (UUID). */
    agentId: string;
    /** Human-readable name of the agent. */
    name: string;
    /** Path to the public key file. */
    publicKeyPath: string;
    /** Path to the configuration file. */
    configPath: string;
}
/**
 * A signed JACS document.
 */
export interface SignedDocument {
    /** The full JSON string of the signed JACS document. */
    raw: string;
    /** Unique identifier for this document (UUID). */
    documentId: string;
    /** ID of the agent that signed this document. */
    agentId: string;
    /** ISO 8601 timestamp of when the document was signed. */
    timestamp: string;
}
/**
 * Result of verifying a signed document.
 */
export interface VerificationResult {
    /** Whether the signature is valid. */
    valid: boolean;
    /** The original data that was signed. */
    data?: any;
    /** ID of the agent that signed the document. */
    signerId: string;
    /** Name of the signer (if available in trust store). */
    signerName?: string;
    /** ISO 8601 timestamp of when the document was signed. */
    timestamp: string;
    /** Any file attachments included in the document. */
    attachments: Attachment[];
    /** Error messages if verification failed. */
    errors: string[];
}
/**
 * A file attachment in a signed document.
 */
export interface Attachment {
    /** Original filename. */
    filename: string;
    /** MIME type of the file. */
    mimeType: string;
    /** File content (decoded if it was embedded). */
    content?: Buffer;
    /** SHA-256 hash of the original file. */
    hash: string;
    /** Whether the file was embedded (true) or referenced (false). */
    embedded: boolean;
}
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
export declare function create(name: string, purpose?: string, keyAlgorithm?: string): AgentInfo;
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
export declare function load(configPath?: string): AgentInfo;
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
export declare function verifySelf(): VerificationResult;
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
export declare function signMessage(data: any): SignedDocument;
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
export declare function updateAgent(newAgentData: any): string;
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
export declare function updateDocument(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): SignedDocument;
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
export declare function signFile(filePath: string, embed?: boolean): SignedDocument;
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
export declare function verify(signedDocument: string): VerificationResult;
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
export declare function getPublicKey(): string;
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
export declare function exportAgent(): string;
/**
 * Get information about the currently loaded agent.
 *
 * @returns AgentInfo if an agent is loaded, null otherwise
 */
export declare function getAgentInfo(): AgentInfo | null;
/**
 * Check if an agent is currently loaded.
 *
 * @returns true if an agent is loaded, false otherwise
 */
export declare function isLoaded(): boolean;
