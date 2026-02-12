/**
 * JACS Express Middleware
 *
 * Factory-based middleware for Express v4/v5 that verifies incoming
 * JACS-signed request bodies and optionally auto-signs JSON responses.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { JacsClient } from './client';
 * import { jacsMiddleware } from './express';
 *
 * const client = await JacsClient.quickstart();
 * const app = express();
 * app.use(express.text({ type: 'application/json' }));
 * app.use(jacsMiddleware({ client, verify: true }));
 *
 * app.post('/api/data', (req, res) => {
 *   console.log(req.jacsPayload); // verified payload
 *   res.json({ status: 'ok' });
 * });
 * ```
 */

import type { JacsClient } from './client.js';

// =============================================================================
// Express-compatible types (avoids requiring @types/express as a dependency)
// =============================================================================

/** Minimal Express-like request shape. */
export interface ExpressRequest {
  method: string;
  body?: any;
  headers: Record<string, any>;
  [key: string]: any;
}

/** Minimal Express-like response shape. */
export interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: any): ExpressResponse;
  send(body: any): ExpressResponse;
  type(val: string): ExpressResponse;
  headersSent: boolean;
  [key: string]: any;
}

/** Express next function. */
export type ExpressNextFunction = (err?: any) => void;

// =============================================================================
// Public types
// =============================================================================

export interface JacsMiddlewareOptions {
  /** Pre-initialized JacsClient instance (preferred). */
  client?: JacsClient;
  /** Path to jacs config file. Used only if `client` is not provided. */
  configPath?: string;
  /** Auto-sign JSON responses via res.json() interception. Default: false (opt-in). */
  sign?: boolean;
  /** Verify incoming POST/PUT/PATCH bodies as JACS documents. Default: true. */
  verify?: boolean;
  /** Allow unsigned/invalid requests to pass through instead of returning 401. Default: false. */
  optional?: boolean;
  /** Enable A2A discovery endpoints at /.well-known/*. Default: false. */
  a2a?: boolean;
  /** A2A skills to advertise in the agent card. */
  a2aSkills?: Array<{ id: string; name: string; description: string; tags: string[] }>;
  /** Base URL / domain for the A2A agent card. */
  a2aUrl?: string;
}

export interface JacsRequest extends ExpressRequest {
  /** Verified JACS payload content (set when verify succeeds). */
  jacsPayload?: any;
  /** JacsClient instance for manual sign/verify in route handlers. */
  jacsClient?: JacsClient;
}

// =============================================================================
// Internal helpers
// =============================================================================

/** Methods that carry a request body. */
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);

async function resolveClient(options: JacsMiddlewareOptions): Promise<JacsClient> {
  if (options.client) {
    return options.client;
  }

  // Lazy-import to avoid hard dependency on client.ts at module level
  const { JacsClient: ClientCtor } = await import('./client.js');

  if (options.configPath) {
    const client = new ClientCtor();
    await client.load(options.configPath);
    return client;
  }

  return ClientCtor.quickstart();
}

// =============================================================================
// Middleware factory
// =============================================================================

/**
 * Create JACS Express middleware.
 *
 * The returned middleware attaches `req.jacsClient` on every request.
 * When `verify` is true (default), POST/PUT/PATCH bodies are verified as
 * JACS-signed documents and the extracted payload is set on `req.jacsPayload`.
 * When `sign` is true, `res.json()` is intercepted to auto-sign the response.
 */
export function jacsMiddleware(options: JacsMiddlewareOptions = {}) {
  const shouldVerify = options.verify !== false;
  const shouldSign = options.sign === true;
  const isOptional = options.optional === true;
  const enableA2A = options.a2a === true;

  // Client is resolved once (lazy, on first request) then cached.
  let clientPromise: Promise<JacsClient> | null = null;

  function getClient(): Promise<JacsClient> {
    if (!clientPromise) {
      clientPromise = resolveClient(options);
    }
    return clientPromise;
  }

  // Pre-resolve immediately if a client is already provided (avoids first-request latency).
  if (options.client) {
    clientPromise = Promise.resolve(options.client);
  }

  // A2A well-known documents are built once and cached.
  let a2aDocuments: Record<string, any> | null = null;
  const A2A_CORS: Record<string, string> = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
    'Access-Control-Max-Age': '86400',
  };

  function getA2ADocuments(client: JacsClient): Record<string, any> {
    if (!a2aDocuments) {
      const { buildWellKnownDocuments } = require('./src/a2a-server');
      a2aDocuments = buildWellKnownDocuments(client, {
        skills: options.a2aSkills,
        url: options.a2aUrl,
      });
    }
    return a2aDocuments!;
  }

  return async function jacsExpressMiddleware(
    req: JacsRequest,
    res: ExpressResponse,
    next: ExpressNextFunction,
  ): Promise<void> {
    let client: JacsClient;
    try {
      client = await getClient();
    } catch (err: any) {
      res.status(500).json({ error: 'JACS initialization failed' });
      return;
    }

    // Always expose the client on the request for manual use in route handlers.
    req.jacsClient = client;

    // ----- A2A well-known endpoints -----
    if (enableA2A && req.path && req.path.startsWith('/.well-known/')) {
      const documents = getA2ADocuments(client);

      if (req.method === 'OPTIONS' && documents[req.path]) {
        for (const [key, value] of Object.entries(A2A_CORS)) {
          res.set(key, value);
        }
        res.status(204).send('');
        return;
      }

      if (req.method === 'GET' && documents[req.path]) {
        for (const [key, value] of Object.entries(A2A_CORS)) {
          res.set(key, value);
        }
        res.json(documents[req.path]);
        return;
      }
    }

    // ----- Verify incoming body -----
    if (shouldVerify && BODY_METHODS.has(req.method)) {
      const rawBody = typeof req.body === 'string' ? req.body : null;

      if (rawBody) {
        try {
          const result = await client.verify(rawBody);
          if (result.valid) {
            req.jacsPayload = result.data;
          } else if (!isOptional) {
            res.status(401).json({ error: 'JACS verification failed', details: result.errors });
            return;
          }
          // When optional and invalid, just continue without jacsPayload.
        } catch (err: any) {
          if (!isOptional) {
            res.status(401).json({ error: 'JACS verification failed', details: [String(err)] });
            return;
          }
        }
      } else if (!isOptional && req.body !== undefined) {
        // Body exists but is not a string — cannot verify.
        // Only reject if body is present; missing body on POST may be handled by route.
      }
    }

    // ----- Auto-sign responses -----
    if (shouldSign) {
      const originalJson = res.json.bind(res);

      res.json = function jacsSignedJson(body: any): ExpressResponse {
        // Fire-and-forget async signing, then send via original json.
        client
          .signMessage(body)
          .then((signed) => {
            originalJson(signed.raw);
          })
          .catch(() => {
            // Signing failed — send unsigned to avoid hanging response.
            originalJson(body);
          });
        return res;
      };
    }

    next();
  };
}
