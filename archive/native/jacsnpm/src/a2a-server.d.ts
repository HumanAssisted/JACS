export interface A2AServerSkill {
  id?: string;
  name: string;
  description?: string;
  tags?: string[];
}

export interface A2AServerOptions {
  /** Must match skills already present in the native signed Agent Card. */
  skills?: A2AServerSkill[];
  /** Must match the public origin already present in the native signed card. */
  url?: string;
  /** Must match the native root algorithm descriptor. */
  keyAlgorithm?: string;
  /** Explicit compatibility selection ('es256'); defaults to the root key. */
  a2aAlgorithm?: string;
}

export interface A2AServerClientLike {
  agentId?: string;
  name?: string;
  _agent?: {
    generateWellKnownDocumentsSync?: (algorithm?: string) => string;
  };
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
