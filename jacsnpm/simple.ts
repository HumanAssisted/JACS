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

import {
  JacsAgent,
  hashString,
  verifyString,
  createConfig,
  createAgent as nativeCreateAgent,
  trustAgent as nativeTrustAgent,
  listTrustedAgents as nativeListTrustedAgents,
  untrustAgent as nativeUntrustAgent,
  isTrusted as nativeIsTrusted,
  getTrustedAgent as nativeGetTrustedAgent,
} from './index';
import * as fs from 'fs';
import * as path from 'path';

// =============================================================================
// Re-exports for advanced usage
// =============================================================================

/**
 * Re-export utilities and classes for advanced use cases.
 * Use these when you need functionality beyond the simplified API.
 */
export { JacsAgent, hashString, verifyString, createConfig };

// =============================================================================
// Types
// =============================================================================

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

// =============================================================================
// Global State
// =============================================================================

let globalAgent: JacsAgent | null = null;
let agentInfo: AgentInfo | null = null;

// =============================================================================
// Core Operations
// =============================================================================

/**
 * Options for creating a new JACS agent.
 */
export interface CreateAgentOptions {
  /** Human-readable name for the agent. */
  name: string;
  /** Password for encrypting the private key. Can also be set via JACS_AGENT_PRIVATE_KEY_PASSWORD env var. */
  password: string;
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
 * The password must be provided directly or via the JACS_AGENT_PRIVATE_KEY_PASSWORD
 * environment variable.
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
export function create(options: CreateAgentOptions): AgentInfo {
  const resultJson = nativeCreateAgent(
    options.name,
    options.password,
    options.algorithm ?? null,
    options.dataDirectory ?? null,
    options.keyDirectory ?? null,
    options.configPath ?? null,
    options.agentType ?? null,
    options.description ?? null,
    options.domain ?? null,
    options.defaultStorage ?? null,
  );

  const info = JSON.parse(resultJson);

  return {
    agentId: info.agent_id || '',
    name: info.name || options.name,
    publicKeyPath: info.public_key_path || `${options.keyDirectory || './jacs_keys'}/jacs.public.pem`,
    configPath: info.config_path || options.configPath || './jacs.config.json',
  };
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
export function load(configPath?: string): AgentInfo {
  const path = configPath || './jacs.config.json';

  if (!fs.existsSync(path)) {
    throw new Error(
      `Config file not found: ${path}\nRun 'jacs create' to create a new agent.`
    );
  }

  // Create new agent instance
  globalAgent = new JacsAgent();
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
export function verifySelf(): VerificationResult {
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
  } catch (e) {
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
export function signMessage(data: any): SignedDocument {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

  // Create document structure
  const docContent = {
    jacsType: 'message',
    jacsLevel: 'raw',
    content: data,
  };

  const result = globalAgent.createDocument(
    JSON.stringify(docContent),
    null,
    null,
    true, // no_save
    null,
    null
  );

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
export function updateAgent(newAgentData: any): string {
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
export function updateDocument(
  documentId: string,
  newDocumentData: any,
  attachments?: string[],
  embed?: boolean
): SignedDocument {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

  const dataString = typeof newDocumentData === 'string'
    ? newDocumentData
    : JSON.stringify(newDocumentData);

  const result = globalAgent.updateDocument(
    documentId,
    dataString,
    attachments || null,
    embed ?? null
  );

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
export function signFile(filePath: string, embed: boolean = false): SignedDocument {
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

  const result = globalAgent.createDocument(
    JSON.stringify(docContent),
    null,
    null,
    true, // no_save
    filePath,
    embed
  );

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
export function verify(signedDocument: string): VerificationResult {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

  // Detect non-JSON input and provide helpful error
  const trimmed = signedDocument.trim();
  if (trimmed.length > 0 && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return {
      valid: false,
      signerId: '',
      timestamp: '',
      attachments: [],
      errors: [
        `Input does not appear to be a JSON document. If you have a document ID (e.g., 'uuid:version'), use verifyById() instead. Received: '${trimmed.substring(0, 50)}${trimmed.length > 50 ? '...' : ''}'`
      ],
    };
  }

  let doc: any;
  try {
    doc = JSON.parse(signedDocument);
  } catch (e) {
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
    const attachments: Attachment[] = (doc.jacsFiles || []).map((f: any) => ({
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
  } catch (e) {
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
export function verifyById(documentId: string): VerificationResult {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

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
    globalAgent.verifyDocumentById(documentId);
    return {
      valid: true,
      signerId: '',
      timestamp: '',
      attachments: [],
      errors: [],
    };
  } catch (e) {
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
export function reencryptKey(oldPassword: string, newPassword: string): void {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

  globalAgent.reencryptKey(oldPassword, newPassword);
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
export function getPublicKey(): string {
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
export function exportAgent(): string {
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
export function getAgentInfo(): AgentInfo | null {
  return agentInfo;
}

/**
 * Check if an agent is currently loaded.
 *
 * @returns true if an agent is loaded, false otherwise
 */
export function isLoaded(): boolean {
  return globalAgent !== null;
}

// =============================================================================
// Agreement Functions
// =============================================================================

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
export function createAgreement(
  document: any,
  agentIds: string[],
  question?: string,
  context?: string,
  fieldName?: string
): SignedDocument {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

  const docString = typeof document === 'string'
    ? document
    : JSON.stringify(document);

  const result = globalAgent.createAgreement(
    docString,
    agentIds,
    question || null,
    context || null,
    fieldName || null
  );

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
export function signAgreement(
  document: any,
  fieldName?: string
): SignedDocument {
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
export function checkAgreement(
  document: any,
  fieldName?: string
): AgreementStatus {
  if (!globalAgent) {
    throw new Error('No agent loaded. Call load() first.');
  }

  const docString = typeof document === 'string'
    ? document
    : JSON.stringify(document);

  const result = globalAgent.checkAgreement(docString, fieldName || null);
  return JSON.parse(result);
}

// =============================================================================
// Trust Store Functions
// =============================================================================

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
export function trustAgent(agentJson: string): string {
  return nativeTrustAgent(agentJson);
}

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
export function listTrustedAgents(): string[] {
  return nativeListTrustedAgents();
}

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
export function untrustAgent(agentId: string): void {
  nativeUntrustAgent(agentId);
}

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
export function isTrusted(agentId: string): boolean {
  return nativeIsTrusted(agentId);
}

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
export function getTrustedAgent(agentId: string): string {
  return nativeGetTrustedAgent(agentId);
}
