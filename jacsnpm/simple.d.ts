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
 * - audit(): Run a read-only security audit and health checks
 *
 * Also re-exports for advanced usage:
 * - JacsAgent: Class for direct agent control
 * - hashString: Standalone SHA-256 hashing
 * - verifyString: Verify with external public key
 * - createConfig: Create agent configuration
 *
 * @example
 * ```typescript
 * import * as jacs from '@hai.ai/jacs/simple';
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
 * Options for HAI registration.
 */
export interface HaiRegistrationOptions {
    /** API key (or set HAI_API_KEY env). */
    apiKey?: string;
    /** HAI base URL (default "https://hai.ai"). */
    haiUrl?: string;
    /** If true, dry-run without sending. */
    preview?: boolean;
}
/**
 * Result of registering an agent with HAI.
 */
export interface HaiRegistrationResult {
    agentId: string;
    jacsId: string;
    dnsVerified: boolean;
    signatures: string[];
}
/**
 * Options for creating a new JACS agent.
 */
export interface CreateAgentOptions {
    /** Human-readable name for the agent. */
    name: string;
    /** Password for encrypting the private key. Falls back to JACS_PRIVATE_KEY_PASSWORD if omitted. */
    password?: string;
    /** Signing algorithm: "pq2025" (default), "ring-Ed25519", or "RSA-PSS". "pq-dilithium" is deprecated. */
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
 * This is a fully programmatic API that does not require interactive input.
 * The password must be provided directly or via the JACS_PRIVATE_KEY_PASSWORD
 * environment variable.
 *
 * @param options - Agent creation options
 * @returns AgentInfo containing the agent ID, name, and file paths
 *
 * @example
 * ```typescript
 * const agent = jacs.create({
 *   name: 'my-agent',
 *   password: process.env.JACS_PRIVATE_KEY_PASSWORD,
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
 * Verify a signed JACS document without loading an agent.
 * Uses caller-supplied key resolution and directories; does not use global agent state.
 *
 * @param signedDocument - Full signed JACS document JSON string
 * @param options - Optional keyResolution, dataDirectory, keyDirectory
 * @returns VerificationResult with valid and signerId
 *
 * @example
 * ```typescript
 * const result = jacs.verifyStandalone(signedJson, { keyResolution: 'local', keyDirectory: './keys' });
 * if (result.valid) console.log(`Signed by: ${result.signerId}`);
 * ```
 */
export declare function verifyStandalone(signedDocument: string, options?: {
    keyResolution?: string;
    dataDirectory?: string;
    keyDirectory?: string;
}): VerificationResult;
/**
 * Verifies a document by its storage ID.
 *
 * Use this when you have a document ID (e.g., "uuid:version") rather than
 * the full JSON string. The document will be loaded from storage and verified.
 *
 * @param documentId - The document ID in "uuid:version" format
 * @returns VerificationResult with the verification status
 *
 * @example
 * ```typescript
 * const result = jacs.verifyById('550e8400-e29b-41d4-a716-446655440000:1');
 * if (result.valid) {
 *   console.log('Document verified');
 * }
 * ```
 */
export declare function verifyById(documentId: string): VerificationResult;
/**
 * Re-encrypt the agent's private key with a new password.
 *
 * @param oldPassword - The current password for the private key
 * @param newPassword - The new password to encrypt with (must meet password requirements)
 *
 * @example
 * ```typescript
 * jacs.reencryptKey('old-password-123!', 'new-Str0ng-P@ss!');
 * console.log('Key re-encrypted successfully');
 * ```
 */
export declare function reencryptKey(oldPassword: string, newPassword: string): void;
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
 * Clear global agent state. Useful for test isolation.
 *
 * After calling reset(), you must call load() or create() again before
 * using any signing or verification functions.
 */
export declare function reset(): void;
/**
 * Return JACS diagnostic info (version, config, agent status).
 *
 * Returns an object with keys like jacs_version, os, arch, agent_loaded,
 * data_directory, key_directory, etc. If an agent is loaded, includes
 * agent_id and agent_version.
 *
 * @returns Diagnostic information object
 */
export declare function debugInfo(): Record<string, unknown>;
/**
 * Returns the DNS TXT record line for the loaded agent (for DNS-based discovery).
 * Format: _v1.agent.jacs.{domain}. TTL IN TXT "v=hai.ai; jacs_agent_id=...; alg=SHA-256; enc=base64; jac_public_key_hash=..."
 */
export declare function getDnsRecord(domain: string, ttl?: number): string;
/**
 * Returns the well-known JSON object for the loaded agent (e.g. for /.well-known/jacs-pubkey.json).
 * Keys: publicKey, publicKeyHash, algorithm, agentId.
 */
export declare function getWellKnownJson(): {
    publicKey: string;
    publicKeyHash: string;
    algorithm: string;
    agentId: string;
};
/**
 * Get comprehensive setup instructions for DNS, DNSSEC, and HAI registration.
 *
 * @param domain - The domain to publish the DNS TXT record under
 * @param ttl - TTL in seconds for the DNS record (default: 3600)
 * @returns Structured setup instructions
 */
export declare function getSetupInstructions(domain: string, ttl?: number): Record<string, unknown>;
/**
 * Register the loaded agent with HAI.ai.
 * Requires a loaded agent (uses exportAgent() for the payload).
 * Calls POST {haiUrl}/api/v1/agents/register with Bearer token and agent JSON.
 *
 * @param options - apiKey (or HAI_API_KEY env), haiUrl (default "https://hai.ai"), preview
 * @returns HaiRegistrationResult with agentId, jacsId, dnsVerified, signatures
 */
export declare function registerWithHai(options?: HaiRegistrationOptions): Promise<HaiRegistrationResult>;
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
 * Add an agent to the local trust store.
 *
 * The trust store is a local list of agents you trust. When verifying
 * documents from known agents, the trust store provides signer names
 * and allows quick lookups.
 *
 * @param agentJson - The agent's JSON document (from their exportAgent())
 * @returns The trusted agent's ID
 *
 * @example
 * ```typescript
 * const trustedId = jacs.trustAgent(partnerAgentJson);
 * console.log(`Trusted agent: ${trustedId}`);
 * ```
 */
export declare function trustAgent(agentJson: string): string;
/**
 * List all trusted agent IDs in the local trust store.
 *
 * @returns Array of trusted agent UUIDs
 *
 * @example
 * ```typescript
 * const trustedIds = jacs.listTrustedAgents();
 * console.log(`${trustedIds.length} trusted agents`);
 * ```
 */
export declare function listTrustedAgents(): string[];
/**
 * Remove an agent from the local trust store.
 *
 * @param agentId - The agent UUID to remove
 *
 * @example
 * ```typescript
 * jacs.untrustAgent('550e8400-e29b-41d4-a716-446655440000');
 * ```
 */
export declare function untrustAgent(agentId: string): void;
/**
 * Check if an agent is in the local trust store.
 *
 * @param agentId - The agent UUID to check
 * @returns true if the agent is trusted
 *
 * @example
 * ```typescript
 * if (jacs.isTrusted(signerId)) {
 *   console.log('Signer is in our trust store');
 * }
 * ```
 */
export declare function isTrusted(agentId: string): boolean;
/**
 * Get a trusted agent's full JSON document from the trust store.
 *
 * @param agentId - The agent UUID to retrieve
 * @returns The agent's JSON document as a string
 *
 * @example
 * ```typescript
 * const agentDoc = JSON.parse(jacs.getTrustedAgent(agentId));
 * console.log(`Agent name: ${agentDoc.jacsAgentName}`);
 * ```
 */
export declare function getTrustedAgent(agentId: string): string;
/**
 * Options for the security audit.
 */
export interface AuditOptions {
    /** Optional path to jacs config file. */
    configPath?: string;
    /** Optional number of recent documents to re-verify. */
    recentN?: number;
}
/**
 * Run a read-only security audit and health checks.
 * Returns an object with risks, health_checks, summary, and related fields.
 *
 * @param options - Optional config path and recent document count
 * @returns Audit result object (risks, health_checks, summary, overall_status)
 *
 * @example
 * ```typescript
 * const result = jacs.audit();
 * console.log(`Risks: ${result.risks.length}, Status: ${result.overall_status}`);
 * ```
 */
export declare function audit(options?: AuditOptions): Record<string, unknown>;
/** Max length for a full verify URL (scheme + host + path + ?s=...). */
export declare const MAX_VERIFY_URL_LEN = 2048;
/** Max UTF-8 byte length of a document that fits in a verify link. */
export declare const MAX_VERIFY_DOCUMENT_BYTES = 1515;
/**
 * Build a verification URL for a signed JACS document (e.g. https://hai.ai/jacs/verify?s=...).
 * Uses URL-safe base64. Throws if the URL would exceed MAX_VERIFY_URL_LEN.
 *
 * @param document - Full signed JACS document string (JSON)
 * @param baseUrl - Base URL of the verifier (no trailing slash). Default "https://hai.ai"
 * @returns Full URL: {baseUrl}/jacs/verify?s={base64url(document)}
 */
export declare function generateVerifyLink(document: string, baseUrl?: string): string;
