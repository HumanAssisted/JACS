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
}
export interface JacsRequest extends ExpressRequest {
    /** Verified JACS payload content (set when verify succeeds). */
    jacsPayload?: any;
    /** JacsClient instance for manual sign/verify in route handlers. */
    jacsClient?: JacsClient;
}
/**
 * Create JACS Express middleware.
 *
 * The returned middleware attaches `req.jacsClient` on every request.
 * When `verify` is true (default), POST/PUT/PATCH bodies are verified as
 * JACS-signed documents and the extracted payload is set on `req.jacsPayload`.
 * When `sign` is true, `res.json()` is intercepted to auto-sign the response.
 */
export declare function jacsMiddleware(options?: JacsMiddlewareOptions): (req: JacsRequest, res: ExpressResponse, next: ExpressNextFunction) => Promise<void>;
