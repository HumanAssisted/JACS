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
import { JacsAgent, hashString, createConfig } from './index';
export { JacsAgent, hashString, createConfig };
export interface AgentInfo {
    agentId: string;
    name: string;
    publicKeyPath: string;
    configPath: string;
}
export interface SignedDocument {
    raw: string;
    documentId: string;
    agentId: string;
    timestamp: string;
}
export interface VerificationResult {
    valid: boolean;
    data?: any;
    signerId: string;
    signerName?: string;
    timestamp: string;
    attachments: Attachment[];
    errors: string[];
}
export interface Attachment {
    filename: string;
    mimeType: string;
    content?: Buffer;
    hash: string;
    embedded: boolean;
}
export interface HaiRegistrationOptions {
    apiKey?: string;
    haiUrl?: string;
    preview?: boolean;
}
export interface HaiRegistrationResult {
    agentId: string;
    jacsId: string;
    dnsVerified: boolean;
    signatures: string[];
}
export interface LoadOptions {
    strict?: boolean;
}
export declare function isStrict(): boolean;
export interface QuickstartOptions {
    algorithm?: string;
    strict?: boolean;
    configPath?: string;
}
export interface QuickstartInfo {
    agentId: string;
    name: string;
    version: string;
    algorithm: string;
}
/**
 * Zero-config quickstart: loads or creates a persistent agent.
 * @returns Promise<QuickstartInfo>
 */
export declare function quickstart(options?: QuickstartOptions): Promise<QuickstartInfo>;
/**
 * Zero-config quickstart (sync variant, blocks event loop).
 */
export declare function quickstartSync(options?: QuickstartOptions): QuickstartInfo;
export interface CreateAgentOptions {
    name: string;
    password?: string;
    algorithm?: string;
    dataDirectory?: string;
    keyDirectory?: string;
    configPath?: string;
    agentType?: string;
    description?: string;
    domain?: string;
    defaultStorage?: string;
}
/**
 * Creates a new JACS agent with cryptographic keys.
 */
export declare function create(options: CreateAgentOptions): Promise<AgentInfo>;
/**
 * Creates a new JACS agent (sync, blocks event loop).
 */
export declare function createSync(options: CreateAgentOptions): AgentInfo;
/**
 * Loads an existing agent from a configuration file.
 */
export declare function load(configPath?: string, options?: LoadOptions): Promise<AgentInfo>;
/**
 * Loads an existing agent (sync, blocks event loop).
 */
export declare function loadSync(configPath?: string, options?: LoadOptions): AgentInfo;
/**
 * Verifies the currently loaded agent's integrity.
 */
export declare function verifySelf(): Promise<VerificationResult>;
/**
 * Verifies the currently loaded agent's integrity (sync).
 */
export declare function verifySelfSync(): VerificationResult;
/**
 * Signs arbitrary data as a JACS message.
 */
export declare function signMessage(data: any): Promise<SignedDocument>;
/**
 * Signs arbitrary data (sync, blocks event loop).
 */
export declare function signMessageSync(data: any): SignedDocument;
/**
 * Updates the agent document with new data and re-signs it.
 */
export declare function updateAgent(newAgentData: any): Promise<string>;
/**
 * Updates the agent document (sync, blocks event loop).
 */
export declare function updateAgentSync(newAgentData: any): string;
/**
 * Updates an existing document with new data and re-signs it.
 */
export declare function updateDocument(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): Promise<SignedDocument>;
/**
 * Updates an existing document (sync, blocks event loop).
 */
export declare function updateDocumentSync(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): SignedDocument;
/**
 * Signs a file with optional content embedding.
 */
export declare function signFile(filePath: string, embed?: boolean): Promise<SignedDocument>;
/**
 * Signs a file (sync, blocks event loop).
 */
export declare function signFileSync(filePath: string, embed?: boolean): SignedDocument;
/**
 * Verifies a signed document and extracts its content.
 */
export declare function verify(signedDocument: string): Promise<VerificationResult>;
/**
 * Verifies a signed document (sync, blocks event loop).
 */
export declare function verifySync(signedDocument: string): VerificationResult;
/**
 * Verify a signed JACS document without loading an agent.
 */
export declare function verifyStandalone(signedDocument: string, options?: {
    keyResolution?: string;
    dataDirectory?: string;
    keyDirectory?: string;
}): VerificationResult;
/**
 * Verifies a document by its storage ID.
 */
export declare function verifyById(documentId: string): Promise<VerificationResult>;
/**
 * Verifies a document by its storage ID (sync, blocks event loop).
 */
export declare function verifyByIdSync(documentId: string): VerificationResult;
/**
 * Re-encrypt the agent's private key with a new password.
 */
export declare function reencryptKey(oldPassword: string, newPassword: string): Promise<void>;
/**
 * Re-encrypt the agent's private key (sync, blocks event loop).
 */
export declare function reencryptKeySync(oldPassword: string, newPassword: string): void;
export declare function getPublicKey(): string;
export declare function exportAgent(): string;
export declare function getAgentInfo(): AgentInfo | null;
export declare function isLoaded(): boolean;
export declare function debugInfo(): Record<string, unknown>;
export declare function reset(): void;
export declare function getDnsRecord(domain: string, ttl?: number): string;
export declare function getWellKnownJson(): {
    publicKey: string;
    publicKeyHash: string;
    algorithm: string;
    agentId: string;
};
export declare function getSetupInstructions(domain: string, ttl?: number): Promise<Record<string, unknown>>;
export declare function getSetupInstructionsSync(domain: string, ttl?: number): Record<string, unknown>;
export declare function registerWithHai(options?: HaiRegistrationOptions): Promise<HaiRegistrationResult>;
export interface AgreementStatus {
    complete: boolean;
    signers: Array<{
        agentId: string;
        signed: boolean;
        signedAt?: string;
    }>;
    pending: string[];
}
export declare function createAgreement(document: any, agentIds: string[], question?: string, context?: string, fieldName?: string): Promise<SignedDocument>;
export declare function createAgreementSync(document: any, agentIds: string[], question?: string, context?: string, fieldName?: string): SignedDocument;
export declare function signAgreement(document: any, fieldName?: string): Promise<SignedDocument>;
export declare function signAgreementSync(document: any, fieldName?: string): SignedDocument;
export declare function checkAgreement(document: any, fieldName?: string): Promise<AgreementStatus>;
export declare function checkAgreementSync(document: any, fieldName?: string): AgreementStatus;
export declare function trustAgent(agentJson: string): string;
export declare function listTrustedAgents(): string[];
export declare function untrustAgent(agentId: string): void;
export declare function isTrusted(agentId: string): boolean;
export declare function getTrustedAgent(agentId: string): string;
export interface AuditOptions {
    configPath?: string;
    recentN?: number;
}
export declare function audit(options?: AuditOptions): Promise<Record<string, unknown>>;
export declare function auditSync(options?: AuditOptions): Record<string, unknown>;
export declare const MAX_VERIFY_URL_LEN = 2048;
export declare const MAX_VERIFY_DOCUMENT_BYTES = 1515;
export declare function generateVerifyLink(document: string, baseUrl?: string): string;
