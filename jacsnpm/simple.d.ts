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
 * - trustAgent(): Add an agent to the local trust store
 * - listTrustedAgents(): List all trusted agent IDs
 * - untrustAgent(): Remove an agent from the trust store
 * - isTrusted(): Check if an agent is trusted
 * - getTrustedAgent(): Get a trusted agent's JSON
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
import { JacsAgent, hashString, verifyString, createConfig } from './index';
/**
 * Re-export utilities and classes for advanced use cases.
 * Use these when you need functionality beyond the simplified API.
 */
export { JacsAgent, hashString, verifyString, createConfig };
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
 * Options for creating a new JACS agent.
 */
export interface CreateAgentOptions {
    /** Human-readable name for the agent. */
    name: string;
    /** Password for encrypting the private key. */
    password: string;
    /** Signing algorithm: "pq2025" (default), "ring-Ed25519", or "RSA-PSS". */
    algorithm?: string;
    /** Directory for agent data (default: "./jacs_data"). */
    dataDirectory?: string;
    /** Directory for cryptographic keys (default: "./jacs_keys"). */
    keyDirectory?: string;
    /** Path to write the config file (default: "./jacs.config.json"). */
    configPath?: string;
    /** Agent type: "ai" (default), "human", or "hybrid". */
    agentType?: string;
    /** Description of the agent's purpose. */
    description?: string;
    /** Domain for DNS-based agent discovery. */
    domain?: string;
    /** Default storage backend: "fs" (default). */
    defaultStorage?: string;
}
/**
 * Creates a new JACS agent with cryptographic keys.
 *
 * @param options - Agent creation options
 * @returns AgentInfo containing the agent ID, name, and file paths
 *
 * @example
 * ```typescript
 * const agent = jacs.create({
 *   name: 'my-agent',
 *   password: process.env.JACS_PASSWORD!,
 *   algorithm: 'pq2025',
 * });
 * console.log(`Created: ${agent.agentId}`);
 * ```
 */
export declare function create(options: CreateAgentOptions): AgentInfo;
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
/**
 * Status of a multi-party agreement.
 */
export interface AgreementStatus {
    /** Whether all required parties have signed. */
    complete: boolean;
    /** List of signers and their status. */
    signers: Array<{
        agentId: string;
        signed: boolean;
        signedAt?: string;
    }>;
    /** List of agent IDs that haven't signed yet. */
    pending: string[];
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
export declare function createAgreement(document: any, agentIds: string[], question?: string, context?: string, fieldName?: string): SignedDocument;
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
export declare function signAgreement(document: any, fieldName?: string): SignedDocument;
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
export declare function checkAgreement(document: any, fieldName?: string): AgreementStatus;
/**
 * Verifies a document by its storage ID.
 *
 * @param documentId - The document ID in "uuid:version" format
 * @returns VerificationResult with the verification status
 */
export declare function verifyById(documentId: string): VerificationResult;
/**
 * Re-encrypt the agent's private key with a new password.
 *
 * @param oldPassword - The current password for the private key
 * @param newPassword - The new password to encrypt with
 */
export declare function reencryptKey(oldPassword: string, newPassword: string): void;
/**
 * Add an agent to the local trust store.
 *
 * @param agentJson - The agent's JSON document
 * @returns The trusted agent's ID
 */
export declare function trustAgent(agentJson: string): string;
/**
 * List all trusted agent IDs in the local trust store.
 *
 * @returns Array of trusted agent UUIDs
 */
export declare function listTrustedAgents(): string[];
/**
 * Remove an agent from the local trust store.
 *
 * @param agentId - The agent UUID to remove
 */
export declare function untrustAgent(agentId: string): void;
/**
 * Check if an agent is in the local trust store.
 *
 * @param agentId - The agent UUID to check
 * @returns true if the agent is trusted
 */
export declare function isTrusted(agentId: string): boolean;
/**
 * Get a trusted agent's full JSON document from the trust store.
 *
 * @param agentId - The agent UUID to retrieve
 * @returns The agent's JSON document as a string
 */
export declare function getTrustedAgent(agentId: string): string;
