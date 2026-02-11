# Koa Middleware

**Sign it. Prove it.** -- in your Koa app.

JACS provides `jacsKoaMiddleware` for Koa with the same design as the [Express middleware](express.md) -- verify incoming signed bodies, optionally auto-sign responses.

## Quick Start

```typescript
import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import { JacsClient } from '@hai.ai/jacs/client';
import { jacsKoaMiddleware } from '@hai.ai/jacs/koa';

const client = await JacsClient.quickstart();
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
jacsKoaMiddleware({
  client?: JacsClient;      // Pre-initialized client (preferred)
  configPath?: string;       // Path to jacs.config.json (if no client)
  sign?: boolean;            // Auto-sign ctx.body after next() (default: false)
  verify?: boolean;          // Verify incoming POST/PUT/PATCH bodies (default: true)
  optional?: boolean;        // Allow unsigned requests through (default: false)
})
```

## How It Works

**Every request** gets `ctx.state.jacsClient` for manual use.

**POST/PUT/PATCH with `verify: true`**: The string body is verified. On success, `ctx.state.jacsPayload` is set. On failure, 401 is returned (unless `optional: true`).

**With `sign: true`**: After downstream middleware runs, if `ctx.body` is a non-Buffer object, it is signed before the response is sent.

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
