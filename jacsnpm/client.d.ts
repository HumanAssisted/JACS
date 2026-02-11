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
import { hashString, createConfig } from './index';
import { generateVerifyLink, MAX_VERIFY_URL_LEN, MAX_VERIFY_DOCUMENT_BYTES } from './simple';
import type { AgentInfo, SignedDocument, VerificationResult, Attachment, AgreementStatus, AuditOptions, QuickstartOptions, QuickstartInfo, CreateAgentOptions, LoadOptions } from './simple';
export type { AgentInfo, SignedDocument, VerificationResult, Attachment, AgreementStatus, AuditOptions, QuickstartOptions, QuickstartInfo, CreateAgentOptions, LoadOptions, };
export { hashString, createConfig, generateVerifyLink, MAX_VERIFY_URL_LEN, MAX_VERIFY_DOCUMENT_BYTES };
export interface AgreementOptions {
    question?: string;
    context?: string;
    fieldName?: string;
    timeout?: string;
    quorum?: number;
    requiredAlgorithms?: string[];
    minimumStrength?: string;
}
export interface JacsClientOptions {
    configPath?: string;
    algorithm?: string;
    strict?: boolean;
}
export declare class JacsClient {
    private agent;
    private info;
    private _strict;
    constructor(options?: JacsClientOptions);
    /**
     * Zero-config factory: loads or creates a persistent agent.
     */
    static quickstart(options?: QuickstartOptions): Promise<JacsClient>;
    /**
     * Zero-config factory (sync variant).
     */
    static quickstartSync(options?: QuickstartOptions): JacsClient;
    /**
     * Create an ephemeral in-memory client for testing.
     */
    static ephemeral(algorithm?: string): Promise<JacsClient>;
    /**
     * Create an ephemeral in-memory client (sync variant).
     */
    static ephemeralSync(algorithm?: string): JacsClient;
    load(configPath?: string, options?: LoadOptions): Promise<AgentInfo>;
    loadSync(configPath?: string, options?: LoadOptions): AgentInfo;
    create(options: CreateAgentOptions): Promise<AgentInfo>;
    createSync(options: CreateAgentOptions): AgentInfo;
    reset(): void;
    dispose(): void;
    [Symbol.dispose](): void;
    get agentId(): string;
    get name(): string;
    get strict(): boolean;
    private requireAgent;
    signMessage(data: any): Promise<SignedDocument>;
    signMessageSync(data: any): SignedDocument;
    verify(signedDocument: string): Promise<VerificationResult>;
    verifySync(signedDocument: string): VerificationResult;
    verifySelf(): Promise<VerificationResult>;
    verifySelfSync(): VerificationResult;
    verifyById(documentId: string): Promise<VerificationResult>;
    verifyByIdSync(documentId: string): VerificationResult;
    signFile(filePath: string, embed?: boolean): Promise<SignedDocument>;
    signFileSync(filePath: string, embed?: boolean): SignedDocument;
    createAgreement(document: any, agentIds: string[], options?: AgreementOptions): Promise<SignedDocument>;
    createAgreementSync(document: any, agentIds: string[], options?: AgreementOptions): SignedDocument;
    signAgreement(document: any, fieldName?: string): Promise<SignedDocument>;
    signAgreementSync(document: any, fieldName?: string): SignedDocument;
    checkAgreement(document: any, fieldName?: string): Promise<AgreementStatus>;
    checkAgreementSync(document: any, fieldName?: string): AgreementStatus;
    updateAgent(newAgentData: any): Promise<string>;
    updateAgentSync(newAgentData: any): string;
    updateDocument(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): Promise<SignedDocument>;
    updateDocumentSync(documentId: string, newDocumentData: any, attachments?: string[], embed?: boolean): SignedDocument;
    trustAgent(agentJson: string): string;
    listTrustedAgents(): string[];
    untrustAgent(agentId: string): void;
    isTrusted(agentId: string): boolean;
    getTrustedAgent(agentId: string): string;
    audit(options?: AuditOptions): Promise<Record<string, unknown>>;
    auditSync(options?: AuditOptions): Record<string, unknown>;
    generateVerifyLink(document: string, baseUrl?: string): string;
}
