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
export declare const JACS_EXTENSION_URI = "urn:hai.ai:jacs-provenance-v1";
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
export interface ArtifactVerificationResult {
    valid: boolean | object;
    signerId: string;
    signerVersion: string;
    artifactType: string;
    timestamp: string;
    originalArtifact: Record<string, unknown>;
    parentSignaturesCount?: number;
    parentVerificationResults?: Array<{
        index: number;
        artifactId: string;
        valid: boolean;
        parentSignaturesValid: boolean;
        error?: string;
    }>;
    parentSignaturesValid?: boolean;
    trustAssessment?: TrustAssessment;
}
export interface TrustAssessment {
    allowed: boolean;
    trustLevel: 'trusted' | 'jacs_registered' | 'untrusted';
    jacsRegistered: boolean;
    inTrustStore: boolean;
    reason: string;
}
export interface A2AQuickstartOptions {
    url?: string;
    name?: string;
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
    jacsServices?: Array<{
        name?: string;
        serviceDescription?: string;
        tools?: Array<{
            function?: {
                name?: string;
                description?: string;
            };
        }>;
    }>;
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
    defaultSkills?: Array<{
        id: string;
        name: string;
        description: string;
        tags: string[];
    }> | null;
    constructor(client: JacsClient, trustPolicy?: TrustPolicy);
    static quickstart(options?: A2AQuickstartOptions): Promise<JACSA2AIntegration>;
    listen(port?: number): Server;
    exportAgentCard(agentData: AgentData): A2AAgentCard;
    createExtensionDescriptor(): Record<string, unknown>;
    /**
     * Assess a remote agent's trust level based on the configured trust policy.
     *
     * - open: allows all agents
     * - verified: requires JACS extension in the agent card
     * - strict: requires the agent to be in the local JACS trust store
     */
    assessRemoteAgent(agentCardJson: string | Record<string, unknown>): TrustAssessment;
    /**
     * Convenience method to add an A2A agent to the JACS trust store.
     * Accepts a raw agent card JSON string or object.
     */
    trustA2AAgent(agentCardJson: string | Record<string, unknown>): string;
    signArtifact(artifact: Record<string, unknown>, artifactType: string, parentSignatures?: Record<string, unknown>[] | null): Promise<Record<string, unknown>>;
    /** @deprecated Use signArtifact() instead. */
    wrapArtifactWithProvenance(artifact: Record<string, unknown>, artifactType: string, parentSignatures?: Record<string, unknown>[] | null): Promise<Record<string, unknown>>;
    verifyWrappedArtifact(wrappedArtifact: Record<string, unknown>): Promise<ArtifactVerificationResult>;
    createChainOfCustody(artifacts: Record<string, unknown>[]): Record<string, unknown>;
    generateWellKnownDocuments(agentCard: A2AAgentCard, jwsSignature: string, publicKeyB64: string, agentData: AgentData): Record<string, Record<string, unknown>>;
    private _hasJacsExtension;
    private _verifyWrappedArtifactInternal;
    private _buildJwks;
    private _inferJwsAlg;
    _slugify(name: string): string;
    private _deriveTags;
    private _convertServicesToSkills;
}
