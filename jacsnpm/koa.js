"use strict";
/**
 * JACS Koa Middleware
 *
 * Factory-based middleware for Koa that verifies incoming JACS-signed
 * request bodies and optionally auto-signs JSON responses.
 *
 * @example
 * ```typescript
 * import Koa from 'koa';
 * import bodyParser from 'koa-bodyparser';
 * import { JacsClient } from './client';
 * import { jacsKoaMiddleware } from './koa';
 *
 * const client = await JacsClient.quickstart();
 * const app = new Koa();
 * app.use(bodyParser({ enableTypes: ['text'] }));
 * app.use(jacsKoaMiddleware({ client, verify: true }));
 *
 * app.use(async (ctx) => {
 *   console.log(ctx.state.jacsPayload); // verified payload
 *   ctx.body = { status: 'ok' };
 * });
 * ```
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.jacsKoaMiddleware = jacsKoaMiddleware;
// =============================================================================
// Internal helpers
// =============================================================================
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
async function resolveClient(options) {
    if (options.client) {
        return options.client;
    }
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
 * Create JACS Koa middleware.
 *
 * Attaches `ctx.state.jacsClient` on every request.
 * When `verify` is true (default), POST/PUT/PATCH bodies are verified and
 * extracted payload is set on `ctx.state.jacsPayload`.
 * When `sign` is true, `ctx.body` is auto-signed after downstream middleware runs.
 */
function jacsKoaMiddleware(options = {}) {
    const shouldVerify = options.verify !== false;
    const shouldSign = options.sign === true;
    const isOptional = options.optional === true;
    let clientPromise = null;
    function getClient() {
        if (!clientPromise) {
            clientPromise = resolveClient(options);
        }
        return clientPromise;
    }
    if (options.client) {
        clientPromise = Promise.resolve(options.client);
    }
    return async function jacsKoaMiddlewareHandler(ctx, next) {
        let client;
        try {
            client = await getClient();
        }
        catch {
            ctx.status = 500;
            ctx.body = { error: 'JACS initialization failed' };
            return;
        }
        // Expose client on context state for manual use in route handlers.
        ctx.state.jacsClient = client;
        // ----- Verify incoming body -----
        if (shouldVerify && BODY_METHODS.has(ctx.method)) {
            // koa-bodyparser puts parsed body on ctx.request.body
            const rawBody = typeof ctx.request.body === 'string'
                ? ctx.request.body
                : typeof ctx.body === 'string' && ctx.method !== 'GET'
                    ? ctx.body
                    : null;
            if (rawBody) {
                try {
                    const result = await client.verify(rawBody);
                    if (result.valid) {
                        ctx.state.jacsPayload = result.data;
                    }
                    else if (!isOptional) {
                        ctx.status = 401;
                        ctx.body = { error: 'JACS verification failed', details: result.errors };
                        return;
                    }
                }
                catch (err) {
                    if (!isOptional) {
                        ctx.status = 401;
                        ctx.body = { error: 'JACS verification failed', details: [String(err)] };
                        return;
                    }
                }
            }
        }
        await next();
        // ----- Auto-sign response -----
        if (shouldSign && ctx.body && typeof ctx.body === 'object' && !Buffer.isBuffer(ctx.body)) {
            try {
                const signed = await client.signMessage(ctx.body);
                ctx.body = signed.raw;
                ctx.type = 'application/json';
            }
            catch {
                // Signing failed — leave the original body intact.
            }
        }
    };
}
//# sourceMappingURL=koa.js.map