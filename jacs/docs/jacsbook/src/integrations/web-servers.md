# Web Servers

JACS provides middleware and utilities for building HTTP servers with cryptographic request/response signing across multiple frameworks and languages.

## Overview

Web server integration with JACS enables:

- **Request Authentication**: Verify incoming requests were signed by valid agents
- **Response Signing**: Automatically sign outgoing responses
- **Tamper Detection**: Ensure message integrity end-to-end
- **Audit Trail**: Track all authenticated interactions

## Supported Frameworks

| Framework | Language | Module |
|-----------|----------|--------|
| Express.js | Node.js | `jacsnpm/http` |
| Koa | Node.js | `jacsnpm/http` |
| FastAPI | Python | `jacs.http` |
| Flask | Python | `jacs.http` |

## Request/Response Flow

All JACS web integrations follow the same flow:

```
Client                          Server
  │                               │
  │── signRequest(payload) ────>  │
  │                               │── verifyRequest()
  │                               │── process request
  │                               │── signResponse(result)
  │<── verifyResponse(result) ──  │
  │
```

## Node.js Integration

### Express.js

```javascript
import express from 'express';
import { JACSExpressMiddleware } from 'jacsnpm/http';

const app = express();

// IMPORTANT: Parse body as text BEFORE JACS middleware
app.use('/api', express.text({ type: '*/*' }));

// Apply JACS middleware
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.config.json'
}));

// Route handlers receive verified payload in req.jacsPayload
app.post('/api/data', (req, res) => {
  const payload = req.jacsPayload;

  if (!payload) {
    return res.status(400).send({ error: 'Invalid JACS request' });
  }

  // Response objects are automatically signed
  res.send({
    received: payload,
    status: 'ok'
  });
});

app.listen(3000);
```

### Koa

```javascript
import Koa from 'koa';
import { JACSKoaMiddleware } from 'jacsnpm/http';

const app = new Koa();

// Apply JACS middleware (handles body parsing internally)
app.use(JACSKoaMiddleware({
  configPath: './jacs.config.json'
}));

app.use(async (ctx) => {
  if (ctx.path === '/api/data' && ctx.method === 'POST') {
    const payload = ctx.state.jacsPayload;

    if (!payload) {
      ctx.status = 400;
      ctx.body = { error: 'Invalid JACS request' };
      return;
    }

    // Response objects are automatically signed
    ctx.body = {
      received: payload,
      status: 'ok'
    };
  }
});

app.listen(3000);
```

See [Node.js HTTP Server](../nodejs/http.md) and [Express Middleware](../nodejs/express.md) for complete documentation.

## Python Integration

### FastAPI

```python
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import jacs
import json

app = FastAPI()

# Initialize JACS agent
agent = jacs.JacsAgent()
agent.load("./jacs.config.json")

@app.post("/api/data")
async def handle_data(request: Request):
    # Read raw body
    body = await request.body()
    body_str = body.decode('utf-8')

    # Verify JACS request
    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        return PlainTextResponse(
            content=json.dumps({"error": "Invalid JACS request"}),
            status_code=400
        )

    # Process request
    result = {"received": payload, "status": "ok"}

    # Sign response
    signed_response = jacs.sign_response(result)

    return PlainTextResponse(content=signed_response)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
```

### Flask

```python
from flask import Flask, request
import jacs
import json

app = Flask(__name__)

# Initialize JACS agent
agent = jacs.JacsAgent()
agent.load("./jacs.config.json")

@app.route("/api/data", methods=["POST"])
def handle_data():
    # Read raw body
    body_str = request.get_data(as_text=True)

    # Verify JACS request
    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        return json.dumps({"error": "Invalid JACS request"}), 400

    # Process request
    result = {"received": payload, "status": "ok"}

    # Sign response
    signed_response = jacs.sign_response(result)

    return signed_response, 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    app.run(port=8000)
```

## HTTP Client

### Node.js Client

```javascript
import jacs from 'jacsnpm';

async function sendJacsRequest(url, payload) {
  // Load JACS agent
  await jacs.load('./jacs.client.config.json');

  // Sign the request
  const signedRequest = await jacs.signRequest(payload);

  // Send HTTP request
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: signedRequest
  });

  // Verify response
  const responseText = await response.text();
  const verified = await jacs.verifyResponse(responseText);

  return verified.payload;
}

// Usage
const result = await sendJacsRequest('http://localhost:3000/api/data', {
  action: 'fetch',
  query: { id: 42 }
});
```

### Python Client

```python
import jacs
import requests
import json

def send_jacs_request(url, payload):
    # Initialize JACS agent
    agent = jacs.JacsAgent()
    agent.load("./jacs.client.config.json")

    # Sign the request
    signed_request = jacs.sign_request(payload)

    # Send HTTP request
    response = requests.post(
        url,
        data=signed_request,
        headers={"Content-Type": "text/plain"}
    )

    # Verify response
    verified = jacs.verify_response(response.text)
    return json.loads(verified).get('payload')

# Usage
result = send_jacs_request("http://localhost:8000/api/data", {
    "action": "fetch",
    "query": {"id": 42}
})
```

## Middleware Patterns

### Route-Level Protection

Protect specific routes while leaving others public:

```javascript
// Node.js Express
const app = express();

// Public routes (no JACS)
app.get('/health', (req, res) => res.send({ status: 'ok' }));
app.get('/public/info', (req, res) => res.send({ name: 'My API' }));

// Protected routes (JACS required)
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: './jacs.config.json' }));

app.post('/api/secure', (req, res) => {
  // Only JACS-signed requests reach here
  res.send({ data: 'secure response' });
});
```

### Multiple Agent Configurations

Use different JACS agents for different route groups:

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

### Validation Middleware

Create reusable validation helpers:

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

## Content-Type Considerations

JACS requests should use `text/plain` content type since they are signed JSON strings:

```javascript
// Client side
const response = await fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'text/plain' },  // Not application/json
  body: signedRequest
});
```

```javascript
// Server side (Express)
app.use('/api', express.text({ type: '*/*' }));  // Parse as text, not JSON
```

## Error Handling

### Server-Side Errors

```javascript
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

### Client-Side Errors

```javascript
try {
  const verified = await jacs.verifyResponse(responseText);
  return verified.payload;
} catch (error) {
  console.error('JACS verification failed:', error.message);
  // Handle invalid/tampered response
}
```

## Security Best Practices

### 1. Use TLS in Production

Always use HTTPS for production deployments:

```javascript
// Client
await sendJacsRequest('https://api.example.com/data', payload);
```

### 2. Separate Server and Client Keys

Each endpoint needs its own JACS identity:

```
project/
├── server/
│   ├── jacs.config.json
│   └── jacs_keys/
│       ├── private.pem
│       └── public.pem
└── client/
    ├── jacs.config.json
    └── jacs_keys/
        ├── private.pem
        └── public.pem
```

### 3. Middleware Order Matters

For Express, ensure correct middleware order:

```javascript
// Correct order
app.use('/api', express.text({ type: '*/*' }));     // 1. Parse body
app.use('/api', JACSExpressMiddleware({ ... }));    // 2. JACS verification

// Wrong order - JACS won't receive string body
app.use('/api', JACSExpressMiddleware({ ... }));
app.use('/api', express.text({ type: '*/*' }));
```

### 4. Avoid JSON Body Parser Conflicts

Don't mix `express.json()` with JACS routes:

```javascript
// JSON for non-JACS routes
app.use('/public', express.json());

// Text for JACS routes
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ ... }));
```

## Logging and Auditing

Log JACS requests for security auditing:

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

## Testing

### Testing with Supertest

```javascript
import request from 'supertest';
import jacs from 'jacsnpm';

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

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `req.jacsPayload` undefined | Wrong middleware order | Put `express.text()` before JACS middleware |
| Response not signed | Sending string instead of object | Use `res.send({ ... })` not `res.send(JSON.stringify(...))` |
| Verification failures | Key mismatch | Ensure compatible JACS configurations |
| Connection refused | Server not running | Verify server is listening on correct port |

### Debug Logging

```javascript
// Node.js
process.env.JACS_DEBUG = 'true';
```

```python
# Python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## See Also

- [Node.js HTTP Server](../nodejs/http.md) - Detailed Node.js documentation
- [Express Middleware](../nodejs/express.md) - Express-specific patterns
- [MCP Integration](mcp.md) - Model Context Protocol support
- [Security Model](../advanced/security.md) - JACS security architecture
