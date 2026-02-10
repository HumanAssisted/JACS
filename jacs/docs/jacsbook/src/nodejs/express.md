# Express Middleware

**Sign it. Prove it.** -- in your Express app.

JACS provides `jacsMiddleware` for Express v4/v5 that verifies incoming signed request bodies and optionally auto-signs JSON responses. No body-parser gymnastics, no monkey-patching.

## 5-Minute Quickstart

### 1. Install

```bash
npm install @hai.ai/jacs express
```

### 2. Create a JACS client

```typescript
import { JacsClient } from '@hai.ai/jacs/client';

const client = await JacsClient.quickstart();
```

### 3. Add signing middleware

```typescript
import express from 'express';
import { jacsMiddleware } from '@hai.ai/jacs/express';

const app = express();
app.use(express.text({ type: 'application/json' }));
app.use(jacsMiddleware({ client, verify: true }));

app.post('/api/data', (req, res) => {
  console.log(req.jacsPayload); // verified payload
  res.json({ status: 'ok' });
});

app.listen(3000);
```

---

## Quick Start

```typescript
import express from 'express';
import { JacsClient } from '@hai.ai/jacs/client';
import { jacsMiddleware } from '@hai.ai/jacs/express';

const client = await JacsClient.quickstart();
const app = express();

app.use(express.text({ type: 'application/json' }));
app.use(jacsMiddleware({ client, verify: true }));

app.post('/api/data', (req, res) => {
  console.log(req.jacsPayload); // verified payload
  res.json({ status: 'ok' });
});

app.listen(3000);
```

## Options

```typescript
jacsMiddleware({
  client?: JacsClient;      // Pre-initialized client (preferred)
  configPath?: string;       // Path to jacs.config.json (if no client)
  sign?: boolean;            // Auto-sign res.json() responses (default: false)
  verify?: boolean;          // Verify incoming POST/PUT/PATCH bodies (default: true)
  optional?: boolean;        // Allow unsigned requests through (default: false)
})
```

If neither `client` nor `configPath` is provided, the middleware calls `JacsClient.quickstart()` on first request.

## What the Middleware Does

**Every request** gets `req.jacsClient` -- a `JacsClient` instance you can use for manual signing/verification in route handlers.

**POST/PUT/PATCH with `verify: true`** (default): The string body is verified as a JACS document. On success, `req.jacsPayload` contains the extracted payload. On failure, a 401 is returned (unless `optional: true`).

**With `sign: true`**: `res.json()` is intercepted to auto-sign the response body before sending.

## Verify Incoming Requests

```typescript
app.use(express.text({ type: 'application/json' }));
app.use(jacsMiddleware({ client }));

app.post('/api/process', (req, res) => {
  if (!req.jacsPayload) {
    return res.status(400).json({ error: 'Missing payload' });
  }

  const { action, data } = req.jacsPayload;
  res.json({ processed: true, action });
});
```

With `optional: true`, unsigned requests pass through with `req.jacsPayload` unset:

```typescript
app.use(jacsMiddleware({ client, optional: true }));

app.post('/api/mixed', (req, res) => {
  if (req.jacsPayload) {
    // Verified JACS request
    res.json({ verified: true, data: req.jacsPayload });
  } else {
    // Unsigned request -- handle accordingly
    res.json({ verified: false });
  }
});
```

## Auto-Sign Responses

Enable `sign: true` to intercept `res.json()` calls:

```typescript
app.use(jacsMiddleware({ client, sign: true }));

app.post('/api/data', (req, res) => {
  // This response will be JACS-signed automatically
  res.json({ result: 42, timestamp: new Date().toISOString() });
});
```

## Manual Signing in Routes

Use `req.jacsClient` for fine-grained control:

```typescript
app.use(jacsMiddleware({ client }));

app.post('/api/custom', async (req, res) => {
  const result = processData(req.jacsPayload);

  // Sign manually
  const signed = await req.jacsClient.signMessage(result);
  res.type('application/json').send(signed.raw);
});
```

## Per-Route Middleware

Apply JACS to specific routes only:

```typescript
const app = express();
const jacs = jacsMiddleware({ client });

// Public routes -- no JACS
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Protected routes
app.use('/api', express.text({ type: 'application/json' }), jacs);

app.post('/api/secure', (req, res) => {
  res.json({ data: req.jacsPayload });
});
```

## Multiple Agents

Use different `JacsClient` instances per route group:

```typescript
const adminClient = await JacsClient.quickstart({ algorithm: 'pq2025' });
const userClient = await JacsClient.quickstart({ algorithm: 'ring-Ed25519' });

app.use('/admin', express.text({ type: 'application/json' }));
app.use('/admin', jacsMiddleware({ client: adminClient }));

app.use('/user', express.text({ type: 'application/json' }));
app.use('/user', jacsMiddleware({ client: userClient }));
```

## Migration from JACSExpressMiddleware

The legacy `JACSExpressMiddleware` from `@hai.ai/jacs/http` still works but is deprecated. To migrate:

| Old | New |
|-----|-----|
| `import { JACSExpressMiddleware } from '@hai.ai/jacs/http'` | `import { jacsMiddleware } from '@hai.ai/jacs/express'` |
| `JACSExpressMiddleware({ configPath: '...' })` | `jacsMiddleware({ configPath: '...' })` |
| Per-request agent init | Shared client, lazy-loaded once |
| `res.send()` monkey-patch | `res.json()` interception (opt-in) |

The new middleware is simpler, faster (no per-request init), and gives you `req.jacsClient` for manual operations.

## Next Steps

- [Koa Middleware](koa.md) - Same pattern for Koa
- [HTTP Server](http.md) - Core HTTP integration concepts
- [Vercel AI SDK](vercel-ai.md) - AI model provenance signing
- [API Reference](api.md) - Complete API documentation
