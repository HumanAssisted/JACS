# Express Middleware

This chapter covers advanced Express.js integration patterns with JACS, building on the basics covered in [HTTP Server](http.md).

## Overview

JACS provides `JACSExpressMiddleware` for seamless integration with Express.js applications:

- Automatic request verification
- Automatic response signing
- Access to verified payloads via `req.jacsPayload`
- Error handling for invalid requests

## Quick Start

```javascript
import express from 'express';
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';

const app = express();

// Required: Parse body as text before JACS middleware
app.use('/api', express.text({ type: '*/*' }));

// Apply JACS middleware
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

// Routes automatically get verified payloads and signed responses
app.post('/api/data', (req, res) => {
  const payload = req.jacsPayload;
  res.send({ received: payload, status: 'ok' });
});

app.listen(3000);
```

## Middleware Configuration

### Basic Configuration

```javascript
JACSExpressMiddleware({
  configPath: './jacs.config.json'  // Required: path to JACS config
})
```

### Per-Route Configuration

Apply JACS to specific routes:

```javascript
const app = express();

// Non-JACS routes (public endpoints)
app.get('/health', (req, res) => res.send({ status: 'ok' }));
app.get('/public/info', (req, res) => res.send({ name: 'My API' }));

// JACS-protected routes
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: './jacs.config.json' }));

app.post('/api/secure', (req, res) => {
  // Only JACS-signed requests reach here
  res.send({ data: 'secure response' });
});
```

### Multiple JACS Agents

Use different JACS agents for different routes:

```javascript
// Admin routes with admin agent
app.use('/admin', express.text({ type: '*/*' }));
app.use('/admin', JACSExpressMiddleware({
  configPath: './jacs.admin.config.json'
}));

// User routes with user agent
app.use('/user', express.text({ type: '*/*' }));
app.use('/user', JACSExpressMiddleware({
  configPath: './jacs.user.config.json'
}));
```

## Request Handling

### Accessing Verified Payload

The middleware attaches the verified payload to `req.jacsPayload`:

```javascript
app.post('/api/process', (req, res) => {
  // req.jacsPayload contains the verified, decrypted payload
  const { action, data, timestamp } = req.jacsPayload;

  console.log('Action:', action);
  console.log('Data:', data);
  console.log('Request timestamp:', timestamp);

  res.send({ processed: true });
});
```

### Handling Missing Payload

If JACS verification fails, `req.jacsPayload` will be undefined:

```javascript
app.post('/api/secure', (req, res) => {
  if (!req.jacsPayload) {
    return res.status(400).json({ error: 'Invalid JACS request' });
  }

  // Process verified payload
  res.send({ success: true });
});
```

### Validation Helper

Create a reusable validation middleware:

```javascript
function requireJacsPayload(req, res, next) {
  if (!req.jacsPayload) {
    return res.status(400).json({
      error: 'JACS verification failed',
      message: 'Request must be signed with valid JACS credentials'
    });
  }
  next();
}

// Apply to routes
app.post('/api/secure', requireJacsPayload, (req, res) => {
  // Guaranteed to have valid req.jacsPayload
  res.send({ data: req.jacsPayload });
});
```

## Response Handling

### Automatic Signing

When you call `res.send()` with an object, the middleware automatically signs it:

```javascript
app.post('/api/data', (req, res) => {
  // This object will be automatically JACS-signed
  res.send({
    result: 'success',
    data: { value: 42 },
    timestamp: new Date().toISOString()
  });
});
```

### Sending Unsigned Responses

To bypass automatic signing, send a string directly:

```javascript
app.post('/api/raw', (req, res) => {
  // String responses are not signed
  res.type('text/plain').send('Raw text response');
});
```

### Custom Response Format

```javascript
app.post('/api/custom', (req, res) => {
  const response = {
    success: true,
    payload: {
      action: 'completed',
      result: processRequest(req.jacsPayload)
    },
    metadata: {
      serverTime: new Date().toISOString(),
      requestId: generateRequestId()
    }
  };

  // Automatically signed before sending
  res.send(response);
});
```

## Error Handling

### Global Error Handler

```javascript
import express from 'express';
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';

const app = express();

app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: './jacs.config.json' }));

app.post('/api/process', (req, res, next) => {
  try {
    if (!req.jacsPayload) {
      throw new Error('Missing JACS payload');
    }

    const result = processData(req.jacsPayload);
    res.send({ result });
  } catch (error) {
    next(error);
  }
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Error:', error.message);

  res.status(500).send({
    error: 'Internal server error',
    message: error.message
  });
});
```

### Typed Errors

```javascript
class JacsValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'JacsValidationError';
    this.statusCode = 400;
  }
}

app.post('/api/validate', (req, res, next) => {
  try {
    if (!req.jacsPayload) {
      throw new JacsValidationError('Invalid JACS request');
    }

    const { requiredField } = req.jacsPayload;
    if (!requiredField) {
      throw new JacsValidationError('Missing required field');
    }

    res.send({ valid: true });
  } catch (error) {
    next(error);
  }
});

// Error handler
app.use((error, req, res, next) => {
  const statusCode = error.statusCode || 500;
  res.status(statusCode).send({
    error: error.name,
    message: error.message
  });
});
```

## Advanced Patterns

### Router-Level Middleware

```javascript
import { Router } from 'express';
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';

// Create a JACS-enabled router
function createJacsRouter(configPath) {
  const router = Router();

  router.use(express.text({ type: '*/*' }));
  router.use(JACSExpressMiddleware({ configPath }));

  return router;
}

// Usage
const apiRouter = createJacsRouter('./jacs.config.json');

apiRouter.post('/users', (req, res) => {
  res.send({ users: getUserList() });
});

apiRouter.post('/orders', (req, res) => {
  res.send({ orders: getOrders(req.jacsPayload.userId) });
});

app.use('/api', apiRouter);
```

### Middleware Composition

Combine JACS with other middleware:

```javascript
import rateLimit from 'express-rate-limit';
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Apply multiple middleware in order
app.use('/api',
  limiter,                              // Rate limiting first
  express.text({ type: '*/*' }),        // Parse body as text
  JACSExpressMiddleware({ configPath: './jacs.config.json' })  // JACS verification
);
```

### Logging Middleware

Log JACS requests for auditing:

```javascript
function jacsLogger(req, res, next) {
  if (req.jacsPayload) {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      jacsPayload: req.jacsPayload,
      ip: req.ip
    }));
  }
  next();
}

app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: './jacs.config.json' }));
app.use('/api', jacsLogger);  // After JACS middleware
```

### Authentication Integration

Combine JACS with user authentication:

```javascript
// JACS middleware first
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: './jacs.config.json' }));

// Then authentication check
function requireAuth(req, res, next) {
  const payload = req.jacsPayload;

  if (!payload || !payload.userId) {
    return res.status(401).send({ error: 'Authentication required' });
  }

  // Attach user to request
  req.user = { id: payload.userId };
  next();
}

app.post('/api/protected', requireAuth, (req, res) => {
  res.send({
    message: `Hello, user ${req.user.id}`,
    data: req.jacsPayload.data
  });
});
```

## Testing

### Unit Testing Routes

```javascript
import request from 'supertest';
import jacs from '@hai-ai/jacs';

describe('JACS API', () => {
  beforeAll(async () => {
    await jacs.load('./jacs.test.config.json');
  });

  it('should accept valid JACS requests', async () => {
    const payload = { action: 'test', data: 'hello' };
    const signedRequest = await jacs.signRequest(payload);

    const response = await request(app)
      .post('/api/echo')
      .set('Content-Type', 'text/plain')
      .send(signedRequest);

    expect(response.status).toBe(200);

    // Verify response is JACS-signed
    const verified = await jacs.verifyResponse(response.text);
    expect(verified.payload.echo).toEqual(payload);
  });

  it('should reject unsigned requests', async () => {
    const response = await request(app)
      .post('/api/echo')
      .set('Content-Type', 'text/plain')
      .send('{"invalid": "request"}');

    expect(response.status).toBe(400);
  });
});
```

### Mock JACS for Testing

```javascript
// test/mocks/jacs.js
export const mockJacs = {
  payload: null,

  setPayload(p) {
    this.payload = p;
  },

  reset() {
    this.payload = null;
  }
};

// Mock middleware for testing
export function mockJacsMiddleware(req, res, next) {
  req.jacsPayload = mockJacs.payload;
  next();
}

// In tests
describe('API without real JACS', () => {
  beforeEach(() => {
    mockJacs.setPayload({ userId: 'test-user', action: 'test' });
  });

  afterEach(() => {
    mockJacs.reset();
  });

  it('processes payload correctly', async () => {
    const response = await request(testApp)
      .post('/api/process')
      .send('test');

    expect(response.status).toBe(200);
  });
});
```

## Complete Application Example

```javascript
import express from 'express';
import { JACSExpressMiddleware } from '@hai-ai/jacs/http';

const app = express();

// Health check (no JACS)
app.get('/health', (req, res) => res.send({ status: 'healthy' }));

// JACS-protected API routes
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

// Validation middleware
function requirePayload(req, res, next) {
  if (!req.jacsPayload) {
    return res.status(400).send({ error: 'Invalid JACS request' });
  }
  next();
}

// Routes
app.post('/api/echo', requirePayload, (req, res) => {
  res.send({ echo: req.jacsPayload });
});

app.post('/api/users', requirePayload, (req, res) => {
  const { name, email } = req.jacsPayload;

  if (!name || !email) {
    return res.status(400).send({ error: 'Name and email required' });
  }

  const user = createUser({ name, email });
  res.send({ user, created: true });
});

app.post('/api/documents', requirePayload, async (req, res) => {
  const { title, content } = req.jacsPayload;

  const document = await createDocument({ title, content });
  res.send({ document });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).send({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`JACS Express server listening on port ${PORT}`);
});
```

## Troubleshooting

### Body Parsing Issues

**Problem**: `req.jacsPayload` is always undefined

**Solution**: Ensure `express.text()` comes before JACS middleware:

```javascript
// Correct
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: '...' }));

// Wrong
app.use('/api', JACSExpressMiddleware({ configPath: '...' }));
app.use('/api', express.text({ type: '*/*' }));
```

### JSON Body Parser Conflict

**Problem**: Using `express.json()` interferes with JACS

**Solution**: Use route-specific middleware:

```javascript
// JSON for non-JACS routes
app.use('/public', express.json());

// Text for JACS routes
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: '...' }));
```

### Response Not Signed

**Problem**: Responses are plain JSON, not JACS-signed

**Solution**: Ensure you're sending an object, not a string:

```javascript
// Will be signed
res.send({ data: 'value' });

// Will NOT be signed
res.send(JSON.stringify({ data: 'value' }));
```

## Next Steps

- [HTTP Server](http.md) - Core HTTP integration concepts
- [MCP Integration](mcp.md) - Model Context Protocol support
- [API Reference](api.md) - Complete API documentation
