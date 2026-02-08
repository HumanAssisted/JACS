export const A2A_PROTOCOL_VERSION: string;
export const JACS_EXTENSION_URI: string;

export class A2AAgentInterface {
  constructor(url: string, protocolBinding: string, tenant?: string | null);
  url: string;
  protocolBinding: string;
  tenant?: string;
}

export class A2AAgentSkill {
  constructor(opts: {
    id: string;
    name: string;
    description: string;
    tags: string[];
    examples?: string[] | null;
    inputModes?: string[] | null;
    outputModes?: string[] | null;
    security?: unknown[] | null;
  });
}

export class A2AAgentExtension {
  constructor(uri: string, description?: string | null, required?: boolean | null);
}

export class A2AAgentCapabilities {
  constructor(opts?: {
    streaming?: boolean | null;
    pushNotifications?: boolean | null;
    extendedAgentCard?: boolean | null;
    extensions?: A2AAgentExtension[] | null;
  });
}

export class A2AAgentCardSignature {
  constructor(jws: string, keyId?: string | null);
}

export class A2AAgentCard {
  constructor(opts: {
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
  });
}

export class JACSA2AIntegration {
  constructor(jacsConfigPath?: string | null);
  exportAgentCard(agentData: Record<string, unknown>): A2AAgentCard;
  createExtensionDescriptor(): Record<string, unknown>;
  wrapArtifactWithProvenance(
    artifact: Record<string, unknown>,
    artifactType: string,
    parentSignatures?: Record<string, unknown>[] | null,
  ): Record<string, unknown>;
  verifyWrappedArtifact(wrappedArtifact: Record<string, unknown>): Record<string, unknown>;
  createChainOfCustody(artifacts: Record<string, unknown>[]): Record<string, unknown>;
  generateWellKnownDocuments(
    agentCard: A2AAgentCard,
    jwsSignature: string,
    publicKeyB64: string,
    agentData: Record<string, unknown>,
  ): Record<string, unknown>;
}
