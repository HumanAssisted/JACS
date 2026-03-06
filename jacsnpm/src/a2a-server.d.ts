export interface A2AServerSkill {
  id?: string;
  name: string;
  description?: string;
  tags?: string[];
}

export interface A2AServerOptions {
  skills?: A2AServerSkill[];
  url?: string;
  keyAlgorithm?: string;
}

export interface A2AServerClientLike {
  agentId?: string;
  name?: string;
}

export declare const CORS_HEADERS: Record<string, string>;

export declare function buildWellKnownDocuments(
  client: A2AServerClientLike,
  options?: A2AServerOptions,
): Record<string, Record<string, unknown>>;

export declare function jacsA2AMiddleware(
  client: A2AServerClientLike,
  options?: A2AServerOptions,
): unknown;
