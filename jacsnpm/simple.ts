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

import { JacsAgent } from './index';
import * as fs from 'fs';
import * as path from 'path';

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
export function create(
  name: string,
  purpose?: string,
  keyAlgorithm?: string
): AgentInfo {
  // This would call the Rust create function when available
  // For now, throw an error directing to CLI
  throw new Error(
    'Agent creation from JS not yet supported. Use CLI: jacs create'
  );
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
