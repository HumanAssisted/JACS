"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.jacsMiddleware = jacsMiddleware;
// =============================================================================
// Internal helpers
// =============================================================================
/** Methods that carry a request body. */
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
async function resolveClient(options) {
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
function jacsMiddleware(options = {}) {
    const shouldVerify = options.verify !== false;
    const shouldSign = options.sign === true;
    const isOptional = options.optional === true;
    // Client is resolved once (lazy, on first request) then cached.
    let clientPromise = null;
    function getClient() {
        if (!clientPromise) {
            clientPromise = resolveClient(options);
        }
        return clientPromise;
    }
    // Pre-resolve immediately if a client is already provided (avoids first-request latency).
    if (options.client) {
        clientPromise = Promise.resolve(options.client);
    }
    return async function jacsExpressMiddleware(req, res, next) {
        let client;
        try {
            client = await getClient();
        }
        catch (err) {
            res.status(500).json({ error: 'JACS initialization failed' });
            return;
        }
        // Always expose the client on the request for manual use in route handlers.
        req.jacsClient = client;
        // ----- Verify incoming body -----
        if (shouldVerify && BODY_METHODS.has(req.method)) {
            const rawBody = typeof req.body === 'string' ? req.body : null;
            if (rawBody) {
                try {
                    const result = await client.verify(rawBody);
                    if (result.valid) {
                        req.jacsPayload = result.data;
                    }
                    else if (!isOptional) {
                        res.status(401).json({ error: 'JACS verification failed', details: result.errors });
                        return;
                    }
                    // When optional and invalid, just continue without jacsPayload.
                }
                catch (err) {
                    if (!isOptional) {
                        res.status(401).json({ error: 'JACS verification failed', details: [String(err)] });
                        return;
                    }
                }
            }
            else if (!isOptional && req.body !== undefined) {
                // Body exists but is not a string — cannot verify.
                // Only reject if body is present; missing body on POST may be handled by route.
            }
        }
        // ----- Auto-sign responses -----
        if (shouldSign) {
            const originalJson = res.json.bind(res);
            res.json = function jacsSignedJson(body) {
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
//# sourceMappingURL=express.js.map