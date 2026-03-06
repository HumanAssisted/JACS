export type TrustPolicy = 'open' | 'verified' | 'strict';

export interface DiscoverAgentOptions {
  timeoutMs?: number;
}

export interface TrustLookupClient {
  isTrusted?: (agentId: string) => boolean;
}

export interface DiscoverAndAssessOptions extends DiscoverAgentOptions {
  policy?: TrustPolicy;
  trustPolicy?: TrustPolicy;
  client?: TrustLookupClient;
  trustStoreEvaluator?: (agentId: string) => boolean;
  isTrusted?: (agentId: string) => boolean;
}

export interface DiscoverAndAssessResult {
  card: Record<string, unknown>;
  jacsRegistered: boolean;
  trustLevel: 'trusted' | 'jacs_registered' | 'untrusted';
  allowed: boolean;
  inTrustStore: boolean;
  policy: TrustPolicy;
  agentId: string | null;
}

export declare const VALID_TRUST_POLICIES: TrustPolicy[];

export declare function discoverAgent(
  url: string,
  options?: DiscoverAgentOptions,
): Promise<Record<string, unknown>>;

export declare function hasJacsExtension(card: Record<string, unknown>): boolean;

export declare function extractAgentId(card: Record<string, unknown>): string | null;

export declare function discoverAndAssess(
  url: string,
  options?: DiscoverAndAssessOptions,
): Promise<DiscoverAndAssessResult>;
