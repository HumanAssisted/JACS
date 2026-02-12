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
import type { JacsClient } from './client.js';
export interface JacsKoaMiddlewareOptions {
    /** Pre-initialized JacsClient instance (preferred). */
    client?: JacsClient;
    /** Path to jacs config file. Used only if `client` is not provided. */
    configPath?: string;
    /** Auto-sign JSON response bodies after next(). Default: false (opt-in). */
    sign?: boolean;
    /** Verify incoming POST/PUT/PATCH bodies as JACS documents. Default: true. */
    verify?: boolean;
    /** Allow unsigned/invalid requests to pass through instead of returning 401. Default: false. */
    optional?: boolean;
    /** Enable A2A discovery endpoints at /.well-known/*. Default: false. */
    a2a?: boolean;
    /** A2A skills to advertise in the agent card. */
    a2aSkills?: Array<{
        id: string;
        name: string;
        description: string;
        tags: string[];
    }>;
    /** Base URL / domain for the A2A agent card. */
    a2aUrl?: string;
}
interface KoaContext {
    request: {
        method: string;
        body?: any;
    };
    state: Record<string, any>;
    body: any;
    status: number;
    method: string;
    path: string;
    type: string;
    set(field: string, value: string): void;
    [key: string]: any;
}
/**
 * Create JACS Koa middleware.
 *
 * Attaches `ctx.state.jacsClient` on every request.
 * When `verify` is true (default), POST/PUT/PATCH bodies are verified and
 * extracted payload is set on `ctx.state.jacsPayload`.
 * When `sign` is true, `ctx.body` is auto-signed after downstream middleware runs.
 */
export declare function jacsKoaMiddleware(options?: JacsKoaMiddlewareOptions): (ctx: KoaContext, next: () => Promise<void>) => Promise<void>;
export {};
