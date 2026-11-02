# Koa Middleware

{{#include ../_snippets/node-registry-status.md}}

**Sign it. Prove it.** -- in your Koa app.

JACS provides `jacsKoaMiddleware` for Koa with the same design as the [Express middleware](express.md) -- verify incoming signed bodies, optionally auto-sign responses.

## Quick Start

```typescript
import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import { JacsClient } from '@hai.ai/jacs/client';
import { jacsKoaMiddleware } from '@hai.ai/jacs/koa';

const client = await JacsClient.quickstart({
  name: 'my-agent',
  domain: 'my-agent.example.com',
});
const app = new Koa();

app.use(bodyParser({ enableTypes: ['text'] }));
app.use(jacsKoaMiddleware({ client, verify: true }));

app.use(async (ctx) => {
  console.log(ctx.state.jacsPayload); // verified payload
  ctx.body = { status: 'ok' };
});

app.listen(3000);
```

## Options

```typescript
interface JacsKoaMiddlewareOptions {
  client?: JacsClient;      // Pre-initialized client (preferred)
  configPath?: string;       // Path to jacs.config.json (if no client)
  sign?: boolean;            // Auto-sign ctx.body after next() (default: false)
  verify?: boolean;          // Verify incoming POST/PUT/PATCH bodies (default: true)
  optional?: boolean;        // Allow unsigned/invalid bodies through (default: false)
  authReplay?: boolean | {   // Signed-body freshness/deduplication (default: false)
    enabled?: boolean;
    maxAgeSeconds?: number;    // default: 30
    clockSkewSeconds?: number; // default: 5
    cacheTtlSeconds?: number;  // default: maxAge + skew
  };
}
```

## How It Works

**Every request** gets `ctx.state.jacsClient` for manual use.

**POST/PUT/PATCH with `verify: true`**: A supplied body is verified. On success, `ctx.state.jacsPayload` is set. On failure, 401 is returned (unless `optional: true`).

**With `sign: true`**: After downstream middleware runs, if `ctx.body` is defined and not a Buffer, it is signed (including JSON scalars) before the response is sent.

## Signed-body replay checks

This option adds freshness and deduplication to signed bodies. It does not authorize a route or bind the HTTP method, URL, body bytes, and audience. Use [request-bound authorization](http.md) and a configured signer policy for that boundary:

```typescript
app.use(
  jacsKoaMiddleware({
    client,
    verify: true,
    authReplay: { enabled: true, maxAgeSeconds: 30, clockSkewSeconds: 5 },
  })
);
```

When enabled, middleware enforces:

- signature timestamp freshness (`maxAgeSeconds` + `clockSkewSeconds`)
- single-use `(signerId, signature)` dedupe inside a TTL cache

Notes:

- Keep this mode scoped to auth-style endpoints.
- Cache is in-memory per process; use a shared cache for multi-instance deployments.

Response signing fails closed by default: errors withhold the unsigned body.
The explicit `allowUnsignedOutput: true` compatibility option relaxes this;
`strict: true` overrides that option. Routes requiring a signed body should
also reject a missing payload, since body verification is not route authorization.

## Auto-Sign Responses

```typescript
app.use(jacsKoaMiddleware({ client, sign: true }));

app.use(async (ctx) => {
  // This will be JACS-signed automatically after next()
  ctx.body = { result: 42, timestamp: new Date().toISOString() };
});
```

## Manual Signing

```typescript
app.use(jacsKoaMiddleware({ client }));

app.use(async (ctx) => {
  const result = processData(ctx.state.jacsPayload);
  const signed = await ctx.state.jacsClient.signMessage(result);
  ctx.type = 'application/json';
  ctx.body = signed.raw;
});
```

## Comparison with Express

| Feature | Express | Koa |
|---------|---------|-----|
| Import | `jacsMiddleware` from `@hai.ai/jacs/express` | `jacsKoaMiddleware` from `@hai.ai/jacs/koa` |
| Client access | `req.jacsClient` | `ctx.state.jacsClient` |
| Payload | `req.jacsPayload` | `ctx.state.jacsPayload` |
| Auto-sign target | `res.json()` interception | `ctx.body` after `next()` |

## Next Steps

- [Express Middleware](express.md) - Express version
- [Vercel AI SDK](vercel-ai.md) - AI model provenance signing
- [API Reference](api.md) - Complete API documentation
