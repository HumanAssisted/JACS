/**
 * JACS Instance-Based Client API
 *
 * Provides `JacsClient`, a class that wraps its own `JacsAgent` instance so
 * multiple clients can coexist in the same process without shared mutable
 * global state. This is the recommended API for new code.
 *
 * @example
 * ```typescript
 * import { JacsClient } from '@hai.ai/jacs/client';
 *
 * const client = JacsClient.quickstart({ algorithm: 'ring-Ed25519' });
 * const signed = client.signMessage({ action: 'approve' });
 * const result = client.verify(signed.raw);
 * console.log(`Valid: ${result.valid}`);
 * ```
 */
import { hashString, verifyString, createConfig } from './index';
import type { AgentInfo, SignedDocument, VerificationResult, Attachment, AgreementStatus, AuditOptions, QuickstartOptions, QuickstartInfo, CreateAgentOptions, LoadOptions } from './simple';
export type { AgentInfo, SignedDocument, VerificationResult, Attachment, AgreementStatus, AuditOptions, QuickstartOptions, QuickstartInfo, CreateAgentOptions, LoadOptions, };
export { hashString, verifyString, createConfig };
export interface AgreementOptions {
    /** Optional question or purpose of the agreement. */
    question?: string;
    /** Optional additional context for signers. */
    context?: string;
    /** Optional custom field name for the agreement (default: "jacsAgreement"). */
    fieldName?: string;
    /** ISO 8601 deadline after which the agreement expires. */
    timeout?: string;
    /** Minimum number of signatures required (M-of-N). */
    quorum?: number;
    /** Only accept signatures from these algorithms. */
    requiredAlgorithms?: string[];
    /** Minimum strength: "classical" or "post-quantum". */
    minimumStrength?: string;
}
export interface JacsClientOptions {
    /** Path to jacs.config.json (default: "./jacs.config.json"). */
    configPath?: string;
    /** Signing algorithm: "pq2025" (default), "ring-Ed25519", or "RSA-PSS". */
    algorithm?: string;
    /** Enable strict mode: verification failures throw instead of returning { valid: false }. */
    strict?: boolean;
}
/**
 * Instance-based JACS client. Each instance owns its own `JacsAgent` and
 * maintains independent state, so multiple clients can coexist in the same
 * process without interference.
 */
export declare class JacsClient {
    private agent;
    private info;
    private _strict;
    constructor(options?: JacsClientOptions);
    /**
     * Zero-config factory: loads or creates a persistent agent.
     *
     * If a config file already exists at `options.configPath` (default
     * `./jacs.config.json`) the agent is loaded from it. Otherwise a new
     * agent is created with auto-generated keys.
     */
    static quickstart(options?: QuickstartOptions): JacsClient;
    /**
     * Create an ephemeral in-memory client for testing.
     * No config files, no key files, no environment variables needed.
     */
    static ephemeral(algorithm?: string): JacsClient;
    /**
     * Load an agent from a configuration file.
     */
    load(configPath?: string, options?: LoadOptions): AgentInfo;
    /**
     * Create a new agent with cryptographic keys.
     */
    create(options: CreateAgentOptions): AgentInfo;
    /**
     * Clear internal state. After calling reset() you must call load(), create(),
     * quickstart(), or ephemeral() again before using signing/verification.
     */
    reset(): void;
    /**
     * Alias for reset(). Satisfies the disposable pattern.
     */
    dispose(): void;
    [Symbol.dispose](): void;
    /** The current agent's UUID. */
    get agentId(): string;
    /** The current agent's human-readable name. */
    get name(): string;
    /** Whether strict mode is enabled. */
    get strict(): boolean;
    private requireAgent;
    /**
     * Sign arbitrary data as a JACS message.
     */
    signMessage(data: any): SignedDocument;
    /**
     * Verify a signed document and extract its content.
     */
    verify(signedDocument: string): VerificationResult;
    /**
     * Verify the loaded agent's integrity.
     */
    verifySelf(): VerificationResult;
    /**
     * Verify a document by its storage ID ("uuid:version").
     */
    verifyById(documentId: string): VerificationResult;
    /**
     * Sign a file with optional content embedding.
     */
    signFile(filePath: string, embed?: boolean): SignedDocument;
    /**
     * Create a multi-party agreement.
     *
     * Supports extended options: timeout, quorum, requiredAlgorithms, minimumStrength.
     */
    createAgreement(document: any, agentIds: string[], options?: AgreementOptions): SignedDocument;
    /**
     * Sign an existing multi-party agreement.
     */
    signAgreement(document: any, fieldName?: string): SignedDocument;
    /**
     * Check the status of a multi-party agreement.
     */
    checkAgreement(document: any, fieldName?: string): AgreementStatus;
    /**
     * Update the agent document with new data and re-sign it.
     */
    updateAgent(newAgentData: any): string;
    /**
     * Update an existing document with new data and re-sign it.
     */
    updateDocument(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): SignedDocument;
    trustAgent(agentJson: string): string;
    listTrustedAgents(): string[];
    untrustAgent(agentId: string): void;
    isTrusted(agentId: string): boolean;
    getTrustedAgent(agentId: string): string;
    audit(options?: AuditOptions): Record<string, unknown>;
}
