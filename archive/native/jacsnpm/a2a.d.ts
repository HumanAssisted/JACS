/**
 * JACS A2A (Agent-to-Agent) Protocol Integration for Node.js
 *
 * This module provides Node.js bindings for JACS's A2A protocol integration,
 * enabling JACS agents to participate in the Agent-to-Agent communication protocol.
 *
 * Implements A2A protocol v0.4.0 (September 2025).
 */
import type { JacsClient } from './client.js';
import type { Server } from 'http';
export declare const A2A_PROTOCOL_VERSION = "0.4.0";
export declare const JACS_EXTENSION_URI = "urn:jacs:provenance-v1";
export declare const JACS_ALGORITHMS: readonly string[];
export declare const TRUST_POLICIES: {
    OPEN: "open";
    VERIFIED: "verified";
    STRICT: "strict";
};
export type TrustPolicy = 'open' | 'verified' | 'strict';
export declare const DEFAULT_TRUST_POLICY: TrustPolicy;
export declare function sha256(data: string): string;
export declare class A2AAgentInterface {
    url: string;
    protocolBinding: string;
    tenant?: string;
    constructor(url: string, protocolBinding: string, tenant?: string | null);
}
export interface A2AAgentSkillOptions {
    id: string;
    name: string;
    description: string;
    tags: string[];
    examples?: string[] | null;
    inputModes?: string[] | null;
    outputModes?: string[] | null;
    security?: unknown[] | null;
}
export declare class A2AAgentSkill {
    id: string;
    name: string;
    description: string;
    tags: string[];
    examples?: string[];
    inputModes?: string[];
    outputModes?: string[];
    security?: unknown[];
    constructor({ id, name, description, tags, examples, inputModes, outputModes, security, }: A2AAgentSkillOptions);
}
export declare class A2AAgentExtension {
    uri: string;
    description?: string;
    required?: boolean;
    constructor(uri: string, description?: string | null, required?: boolean | null);
}
export interface A2AAgentCapabilitiesOptions {
    streaming?: boolean | null;
    pushNotifications?: boolean | null;
    extendedAgentCard?: boolean | null;
    extensions?: A2AAgentExtension[] | null;
}
export declare class A2AAgentCapabilities {
    streaming?: boolean;
    pushNotifications?: boolean;
    extendedAgentCard?: boolean;
    extensions?: A2AAgentExtension[];
    constructor({ streaming, pushNotifications, extendedAgentCard, extensions, }?: A2AAgentCapabilitiesOptions);
}
export declare class A2AAgentCardSignature {
    jws: string;
    keyId?: string;
    constructor(jws: string, keyId?: string | null);
}
export interface A2AAgentCardOptions {
    name: string;
    description: string;
    version: string;
    protocolVersions: string[];
    supportedInterfaces: A2AAgentInterface[];
    defaultInputModes: string[];
    defaultOutputModes: string[];
    capabilities: A2AAgentCapabilities;
    skills: A2AAgentSkill[];
    provider?: unknown;
    documentationUrl?: string | null;
    iconUrl?: string | null;
    securitySchemes?: Record<string, unknown> | null;
    security?: unknown[] | null;
    signatures?: A2AAgentCardSignature[] | null;
    metadata?: Record<string, unknown> | null;
}
export declare class A2AAgentCard {
    name: string;
    description: string;
    version: string;
    protocolVersions: string[];
    supportedInterfaces: A2AAgentInterface[];
    defaultInputModes: string[];
    defaultOutputModes: string[];
    capabilities: A2AAgentCapabilities;
    skills: A2AAgentSkill[];
    provider?: unknown;
    documentationUrl?: string;
    iconUrl?: string;
    securitySchemes?: Record<string, unknown>;
    security?: unknown[];
    signatures?: A2AAgentCardSignature[];
    metadata?: Record<string, unknown>;
    constructor({ name, description, version, protocolVersions, supportedInterfaces, defaultInputModes, defaultOutputModes, capabilities, skills, provider, documentationUrl, iconUrl, securitySchemes, security, signatures, metadata, }: A2AAgentCardOptions);
}
export interface TrustBlock {
    policy: string | null;
    status: 'allowed' | 'blocked' | 'not_assessed';
    reason: string;
}
export type VerificationStatus = 'Verified' | 'SelfSigned' | {
    Unverified: {
        reason: string;
    };
} | {
    Invalid: {
        reason: string;
    };
};
export interface ParentVerificationResult {
    index: number;
    artifactId: string;
    signerId: string;
    status: VerificationStatus;
    verified: boolean;
    /** Backward-compatibility alias exposed as a non-enumerable property at runtime. */
    valid?: boolean;
}
export interface ArtifactVerificationResult {
    valid: boolean;
    status: VerificationStatus;
    /**
     * @deprecated Canonical A2A verification exposes authenticated payload data
     * through originalArtifact. Legacy verifyResponse() output is never
     * projected into an A2A verification result.
     */
    verifiedPayload?: Record<string, unknown>;
    /**
     * Backward-compatibility field: raw verification output.
     */
    verificationResult?: boolean | Record<string, unknown>;
    signerId: string;
    signerVersion: string;
    artifactType: string;
    timestamp: string;
    originalArtifact: Record<string, unknown>;
    trustLevel?: 'Untrusted' | 'JacsVerified' | 'ExplicitlyTrusted';
    parentSignaturesValid: boolean;
    parentVerificationResults: ParentVerificationResult[];
    parentSignaturesCount?: number;
    /** Trust assessment block, present when policy-aware verify is used. */
    trust?: TrustBlock;
    trustAssessment?: TrustAssessment;
}
export interface TrustAssessment {
    allowed: boolean;
    trustLevel: 'ExplicitlyTrusted' | 'JacsVerified' | 'Untrusted' | 'trusted' | 'jacs_registered' | 'untrusted';
    jacsRegistered: boolean;
    inTrustStore: boolean;
    reason: string;
    policy?: string;
    agentId?: string | null;
    /** True only when the verifying origin key was pinned during this assessment. */
    firstContact: boolean;
}
export interface A2AQuickstartOptions {
    url?: string;
    name?: string;
    domain?: string;
    description?: string;
    /**
     * @deprecated Wrapper-supplied skills cannot be added after the native Agent
     * Card is signed. Non-empty values fail immediately; persist skills through
     * the native agent/card configuration before generating discovery documents.
     */
    skills?: Array<{
        id: string;
        name: string;
        description: string;
        tags: string[];
    }>;
    trustPolicy?: TrustPolicy;
    algorithm?: string;
    configPath?: string;
}
export interface AgentData {
    jacsId?: string;
    jacsName?: string;
    jacsDescription?: string;
    jacsVersion?: string;
    jacsAgentType?: string;
    jacsAgentDomain?: string;
    skills?: Array<A2AAgentSkill | (Partial<A2AAgentSkillOptions> & {
        [key: string]: unknown;
    })>;
    a2aSkills?: Array<A2AAgentSkill | (Partial<A2AAgentSkillOptions> & {
        [key: string]: unknown;
    })>;
    keyAlgorithm?: string;
    jwks?: {
        keys: unknown[];
    };
    jwk?: Record<string, unknown>;
    [key: string]: unknown;
}
export declare class JACSA2AIntegration {
    client: JacsClient;
    trustPolicy: TrustPolicy;
    defaultUrl?: string | null;
    /** Compatibility assertion only; cannot mutate the native signed Agent Card. */
    defaultSkills?: Array<{
        id: string;
        name: string;
        description: string;
        tags: string[];
    }> | null;
    constructor(client: JacsClient, trustPolicy?: TrustPolicy);
    static quickstart(options?: A2AQuickstartOptions): Promise<JACSA2AIntegration>;
    /**
     * Start a minimal Express discovery server for this agent.
     *
     * Pass `port = 0` to let the OS pick an available ephemeral port.
     */
    listen(port?: number): Server;
    exportAgentCard(agentData: AgentData): A2AAgentCard;
    createExtensionDescriptor(): Record<string, unknown>;
    /**
     * Assess a remote agent's trust level based on the configured trust policy.
     *
     * - open: allows all agents
     * - verified: requires native JWS/JWKS verification plus durable TOFU pinning
     * - strict: additionally requires an explicitly trusted native root and its
     *   valid compatibility binding for the exact ES256 card key
     */
    assessRemoteAgent(agentCardJson: string | Record<string, unknown>): TrustAssessment;
    /**
     * Explicitly trust the native JACS identity used by A2A strict mode.
     *
     * An Agent Card is self-advertised discovery metadata and is never enough
     * to create native identity trust. Obtain the full self-signed native JACS
     * agent document and its public key through an authenticated out-of-band
     * channel. The native trust API verifies the document before persisting it.
     */
    trustA2AAgent(agentDocumentJson: string | Record<string, unknown>, publicKeyPem: string): string;
    /**
     * Sign through the native canonical A2A primitive and return the direct
     * `a2a-*` document. Generic request-envelope fallback is never used. The
     * returned portable-v2 metadata and parent chain must exactly match the
     * requested artifact contract before any result is released.
     */
    signArtifact(artifact: Record<string, unknown>, artifactType: string, parentSignatures?: Record<string, unknown>[] | null): Promise<Record<string, unknown>>;
    /** @deprecated Use signArtifact() instead. */
    wrapArtifactWithProvenance(artifact: Record<string, unknown>, artifactType: string, parentSignatures?: Record<string, unknown>[] | null): Promise<Record<string, unknown>>;
    /**
     * Verify artifact cryptography and its parent chain. Supply the real remote
     * Agent Card to additionally enforce this integration's trust policy.
     * Affirmative verification requires the native canonical
     * verifyA2aArtifactSync contract. Legacy verifyResponse is never used as an
     * A2A fallback and cannot project provenance or elevate trust.
     */
    verifyWrappedArtifact(wrappedArtifact: Record<string, unknown>, agentCard?: Record<string, unknown>): Promise<ArtifactVerificationResult>;
    createChainOfCustody(artifacts: Record<string, unknown>[]): Record<string, unknown>;
    generateWellKnownDocuments(agentCard: A2AAgentCard, jwsSignature: string, publicKeyB64: string, agentData: AgentData): Record<string, Record<string, unknown>>;
    private _hasJacsExtension;
    private _legacyAssessRemoteAgent;
    private _buildCanonicalTrustAssessment;
    private _normalizeTrustAssessment;
    private _normalizeParentVerificationResult;
    private _canonicalResultFromWrappedArtifact;
    private _attachCompatibilityAliases;
    private _verifyWrappedArtifactInternal;
    private _buildJwks;
    _slugify(name: string): string;
    private _normalizeA2ASkills;
}
