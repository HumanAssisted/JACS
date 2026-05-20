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
import { JacsAgent, hashString, createConfig } from './index';
import type { AgentInfo, SignedDocument, VerificationResult, Attachment, AgreementStatus, AttestationVerificationResult, DsseEnvelope, AuditOptions, QuickstartOptions, QuickstartInfo, CreateAgentOptions, LoadOptions } from './simple';
export type { AgentInfo, SignedDocument, VerificationResult, Attachment, AgreementStatus, AttestationVerificationResult, DsseEnvelope, AuditOptions, QuickstartOptions, QuickstartInfo, CreateAgentOptions, LoadOptions, };
export { hashString, createConfig };
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
export interface RotationResult {
    jacs_id: string;
    old_version: string;
    new_version: string;
    new_public_key_pem: string;
    new_public_key_hash: string;
    signed_agent_json: string;
    transition_proof: string | null;
}
export interface ClientArtifactVerificationResult {
    valid: boolean;
    /**
     * Extracted payload returned by native verifyResponse() when available.
     */
    verifiedPayload?: Record<string, unknown>;
    /**
     * Backward-compatibility field for one release: raw native verifyResponse() output.
     */
    verificationResult?: boolean | Record<string, unknown>;
    signerId: string;
    signerVersion: string;
    artifactType: string;
    timestamp: string;
    originalArtifact: Record<string, unknown>;
    error?: string;
}
export interface SignTextOptions {
    noBackup?: boolean;
}
export interface VerifyTextOptions {
    /**
     * C1: when true, missing signatures reject the Promise with
     * /no JACS signature found/. Default false.
     */
    strict?: boolean;
    /**
     * PRD §4.1.5: directory of `<signer_id>.public.pem` files for offline
     * verification.
     */
    keyDir?: string;
}
export interface SignImageOptions {
    /**
     * PRD §4.2.4: enable LSB embedding for re-encode survivability
     * (PNG/JPEG only). Default false (Q4).
     */
    robust?: boolean;
    /** Optional explicit format override ("png" | "jpeg" | "webp"). */
    format?: string;
    /**
     * PRD §4.2.2: refuse if the input image already carries a JACS
     * signature.
     */
    refuseOverwrite?: boolean;
}
export interface VerifyImageOptions {
    /** C1: see [VerifyTextOptions.strict]. */
    strict?: boolean;
    /** PRD §4.1.5: see [VerifyTextOptions.keyDir]. */
    keyDir?: string;
    /**
     * PRD §4.2.4: scan the LSB channel as a fallback when the metadata
     * payload is missing. Default false.
     */
    robust?: boolean;
}
export interface ExtractMediaOptions {
    /** PRD §3.2: when true, return base64url wire form. Default false. */
    rawPayload?: boolean;
}
export declare class JacsClient {
    private agent;
    /**
     * Auxiliary `JacsSimpleAgent` used by the inline-text / image methods
     * (signText / verifyText / signImage / verifyImage / extractMediaSignature).
     *
     * `JacsAgent` exposes the broader v0.x API, while these new operations live
     * on `SimpleAgentWrapper` and are surfaced through `JacsSimpleAgent`. We
     * create a separate instance per `JacsClient` so the inline-text/image
     * methods are routable; for ephemeral clients this means JacsAgent and
     * JacsSimpleAgent have distinct keys (acceptable for the smoke-level test
     * coverage in this task — see Task 11 acceptance criteria).
     */
    private simpleAgent;
    private info;
    private _strict;
    constructor(options?: JacsClientOptions);
    /**
     * Factory: loads or creates a persistent agent.
     */
    static quickstart(options: QuickstartOptions): Promise<JacsClient>;
    /**
     * Factory (sync variant).
     */
    static quickstartSync(options: QuickstartOptions): JacsClient;
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
    /**
     * Internal access to the native JacsAgent for A2A and other low-level integrations.
     * @internal
     */
    get _agent(): JacsAgent;
    private requireAgent;
    private withPrivateKeyPassword;
    private withPrivateKeyPasswordSync;
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
    private requireSimpleAgent;
    /**
     * Sign a text/markdown file in place by appending an inline JACS
     * signature block (PRD §4.1).
     */
    signText(filePath: string, options?: SignTextOptions): Promise<any>;
    signTextSync(filePath: string, options?: SignTextOptions): any;
    /**
     * Verify inline JACS signatures in a text/markdown file (PRD §4.1, C1).
     * In permissive mode (default), missing-signature returns
     * `{ status: 'missing_signature' }`. In strict mode the Promise rejects
     * with `/no JACS signature found/`.
     */
    verifyText(filePath: string, options?: VerifyTextOptions): Promise<any>;
    verifyTextSync(filePath: string, options?: VerifyTextOptions): any;
    /**
     * Sign a PNG / JPEG / WebP image by embedding a JACS signature
     * (PRD §4.2). `outputPath` may equal `inputPath` for in-place writes.
     */
    signImage(inputPath: string, outputPath: string, options?: SignImageOptions): Promise<any>;
    signImageSync(inputPath: string, outputPath: string, options?: SignImageOptions): any;
    /**
     * Verify an embedded JACS signature in an image (PRD §4.2, C1).
     */
    verifyImage(filePath: string, options?: VerifyImageOptions): Promise<any>;
    verifyImageSync(filePath: string, options?: VerifyImageOptions): any;
    /**
     * Extract the JACS signature payload embedded in a signed image
     * (PRD §3.2). Returns the decoded JACS signed-document JSON string by
     * default; pass `{ rawPayload: true }` for the base64url wire form.
     * Returns `null` when the input has no JACS signature.
     */
    extractMediaSignature(filePath: string, options?: ExtractMediaOptions): Promise<string | null>;
    extractMediaSignatureSync(filePath: string, options?: ExtractMediaOptions): string | null;
    /**
     * Convert a JSON string to YAML.
     */
    toYaml(jsonStr: string): Promise<string>;
    toYamlSync(jsonStr: string): string;
    /**
     * Convert a YAML string to pretty-printed JSON.
     */
    fromYaml(yamlStr: string): Promise<string>;
    fromYamlSync(yamlStr: string): string;
    /**
     * Convert a JSON string to a self-contained HTML document.
     */
    toHtml(jsonStr: string): Promise<string>;
    toHtmlSync(jsonStr: string): string;
    /**
     * Extract JSON from an HTML document produced by toHtml().
     */
    fromHtml(htmlStr: string): Promise<string>;
    fromHtmlSync(htmlStr: string): string;
    /**
     * Convert YAML to JSON and verify the resulting document.
     */
    verifyYaml(yamlStr: string): Promise<boolean>;
    verifyYamlSync(yamlStr: string): boolean;
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
    trustAgentWithKey(agentJson: string, publicKeyPem: string): string;
    listTrustedAgents(): string[];
    untrustAgent(agentId: string): void;
    isTrusted(agentId: string): boolean;
    getTrustedAgent(agentId: string): string;
    getPublicKey(): string;
    /**
     * Rotate the agent's cryptographic keys.
     *
     * Generates a new keypair, archives the old keys, creates a new agent
     * version, and re-signs the config file.
     *
     * @param options - Optional. `{ algorithm?: string }` to change the signing algorithm.
     * @returns Rotation result with old_version, new_version, transition_proof, etc.
     */
    rotateKeys(options?: {
        algorithm?: string;
    }): Promise<RotationResult>;
    /**
     * Rotate the agent's cryptographic keys (sync variant).
     */
    rotateKeysSync(options?: {
        algorithm?: string;
    }): RotationResult;
    exportAgent(): string;
    /** @deprecated Use getPublicKey() instead. */
    sharePublicKey(): string;
    /** @deprecated Use exportAgent() instead. */
    shareAgent(): string;
    audit(options?: AuditOptions): Promise<Record<string, unknown>>;
    auditSync(options?: AuditOptions): Record<string, unknown>;
    /**
     * Create a signed attestation document.
     *
     * @param params - Object with subject, claims, and optional evidence/derivation/policyContext.
     * @returns The signed attestation document as a SignedDocument.
     */
    createAttestation(params: {
        subject: Record<string, unknown>;
        claims: Record<string, unknown>[];
        evidence?: Record<string, unknown>[];
        derivation?: Record<string, unknown>;
        policyContext?: Record<string, unknown>;
    }): Promise<SignedDocument>;
    /**
     * Verify an attestation document.
     *
     * The returned object preserves the canonical wire-format field names from the
     * attestation/DSSE JSON contracts, which use camelCase.
     *
     * @param attestationJson - Raw JSON string of the attestation document.
     * @param opts - Optional. Set full: true for full-tier verification.
     * @returns Verification result with valid, crypto, evidence, chain, errors.
     */
    verifyAttestation(attestationJson: string, opts?: {
        full?: boolean;
    }): Promise<AttestationVerificationResult>;
    /**
     * Lift a signed document into an attestation.
     *
     * @param signedDocJson - Raw JSON string of the signed document.
     * @param claims - Array of claim objects.
     * @returns The lifted attestation as a SignedDocument.
     */
    liftToAttestation(signedDocJson: string, claims: Record<string, unknown>[]): Promise<SignedDocument>;
    /**
     * Export an attestation as a DSSE (Dead Simple Signing Envelope).
     *
     * @param attestationJson - Raw JSON string of the attestation document.
     * @returns The DSSE envelope as a parsed object.
     */
    exportAttestationDsse(attestationJson: string): Promise<DsseEnvelope>;
    /**
     * Get a configured JACSA2AIntegration instance bound to this client.
     *
     * @example
     * ```typescript
     * const a2a = client.getA2A();
     * const card = a2a.exportAgentCard({ jacsId: client.agentId, ... });
     * const signed = await a2a.signArtifact(artifact, 'artifact');
     * ```
     */
    getA2A(): any;
    /**
     * Export this agent as an A2A Agent Card.
     *
     * @param agentData - A2A agent card data (jacsId, jacsName, skills, etc.).
     *   If not provided, a minimal card is built from the client's own info.
     */
    exportAgentCard(agentData?: Record<string, unknown>): any;
    /**
     * Sign an A2A artifact with this agent's JACS provenance.
     *
     * @param artifact - The artifact payload to sign.
     * @param artifactType - Type label (e.g., "artifact", "result").
     * @param parentSignatures - Optional parent signatures for chain of custody.
     */
    signArtifact(artifact: Record<string, unknown>, artifactType: string, parentSignatures?: Record<string, unknown>[] | null): Promise<Record<string, unknown>>;
    /**
     * Verify a JACS-signed A2A artifact.
     *
     * Accepts the raw JSON string from signArtifact() or a parsed object.
     * When a string is given it is passed directly to verifyResponse to
     * preserve the original serialization and hash.
     *
     * @param wrappedArtifact - The signed artifact (string or object).
     */
    verifyArtifact(wrappedArtifact: string | Record<string, unknown>): Promise<ClientArtifactVerificationResult>;
    /**
     * Generate .well-known documents for A2A discovery.
     *
     * @param agentCard - The A2A Agent Card (from exportAgentCard).
     * @param jwsSignature - JWS signature of the Agent Card.
     * @param publicKeyB64 - Base64-encoded public key.
     * @param agentData - JACS agent data for metadata.
     */
    generateWellKnownDocuments(agentCard: any, jwsSignature: string, publicKeyB64: string, agentData: Record<string, unknown>): Record<string, Record<string, unknown>>;
}
