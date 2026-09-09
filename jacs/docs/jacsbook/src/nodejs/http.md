# HTTP Server

{{#include ../_snippets/node-registry-status.md}}

JACS provides middleware and utilities for carrying signed documents over
HTTP. The legacy middleware on this page is an artifact-integrity layer, not a
complete HTTP authentication protocol.

> **Security boundary:** `signRequest()` / `verifyResponse()` do not bind the
> actual method, absolute URL, query, exact body bytes, or service audience. Do
> not use them alone to authorize an endpoint. Source `0.12.0` clients use
> `JacsSimpleAgent.buildRequestAuthHeader(method, url, body, audience)` for a `JACS v2`
> credential. Servers verify the same request context with a trusted key and
> atomically consume its nonce. Signed events use `signResponse()` on
> `JacsSimpleAgent` and fail-closed `unwrapSignedEvent()` with pinned server
> keys. See [Security](../advanced/security.md#request-bound-http-authorization).

## Overview

JACS HTTP integration provides:

- **Artifact signing**: Carry generic signed JACS documents in request bodies
- **Artifact verification**: Verify those document signatures and hashes
- **Request-bound auth**: Build a separate `JACS v2` Authorization header
- **Strict events**: Verify the complete v2 response envelope with pinned keys
- **Framework middleware**: Ready-to-use middleware for Express and Koa

## Core Concepts

### Request/Response Flow

```
Client                          Server
  |                               |
  |-- Authorization: JACS v2 ---> |-- verify method/URL/body/audience
  |-- exact body bytes ---------> |-- atomically consume nonce
  |                               |-- process payload
  |                               |-- JacsSimpleAgent.signResponse(result)
  |<-- v2 signed envelope -------|
  |-- unwrapSignedEvent(envelope, pinnedKeys)
  |
```

Successful verification proves possession of the private key corresponding to
the key selected by the verifier and integrity of the signed scope. It does not
independently establish a person, organization, domain, or other real-world
identity; that association comes from configured trust.

## HTTP Client

### Basic Client Usage

```javascript
import jacs from '@hai.ai/jacs';
import http from 'http';

async function main() {
  // Load JACS agent
  await jacs.load('./jacs.config.json');

  // Prepare payload
  const payload = {
    message: "Hello, secure server!",
    data: { id: 123, value: "some data" },
    timestamp: new Date().toISOString()
  };

  // Sign the request
  const signedRequest = await jacs.signRequest(payload);

  // Send HTTP request
  const response = await sendRequest(signedRequest, 'localhost', 3000, '/api/echo');

  // Verify the response
  const verifiedResponse = await jacs.verifyResponse(response);
  console.log('Verified payload:', verifiedResponse.payload);
}

function sendRequest(body, host, port, path) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: host,
      port: port,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

main();
```

### Using Fetch

```javascript
import jacs from '@hai.ai/jacs';

async function sendJacsRequest(url, payload) {
  await jacs.load('./jacs.config.json');

  // Sign the payload
  const signedRequest = await jacs.signRequest(payload);

  // Send request
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: signedRequest
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

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

## Express Server

### Using Express Middleware

JACS provides `JACSExpressMiddleware` that automatically:
- Verifies incoming JACS requests
- Attaches the verified payload to `req.jacsPayload`
- Signs outgoing responses when you call `res.send()` with an object

```javascript
import express from 'express';
import { JACSExpressMiddleware } from '@hai.ai/jacs/http';

const app = express();
const PORT = 3000;

// IMPORTANT: Use express.text() BEFORE JACS middleware
// This ensures req.body is a string for JACS verification
app.use('/api', express.text({ type: '*/*' }));

// Apply JACS middleware to API routes
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.server.config.json'
}));

// Route handler
app.post('/api/echo', (req, res) => {
  // Access verified payload from req.jacsPayload
  const payload = req.jacsPayload;

  if (!payload) {
    return res.status(400).send('JACS payload missing');
  }

  console.log('Received verified payload:', payload);

  // Send response object - middleware will sign it automatically
  res.send({
    echo: "Server says hello!",
    received: payload,
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`JACS Express server listening on port ${PORT}`);
});
```

### Middleware Configuration

```javascript
JACSExpressMiddleware({
  configPath: './jacs.config.json'  // Required: path to JACS config
})
```

### Manual Request/Response Handling

For more control, you can handle signing manually:

```javascript
import express from 'express';
import jacs from '@hai.ai/jacs';

const app = express();

// Initialize JACS once at startup
await jacs.load('./jacs.config.json');

app.use(express.text({ type: '*/*' }));

app.post('/api/process', async (req, res) => {
  try {
    // Manually verify incoming request
    const verified = await jacs.verifyResponse(req.body);
    const payload = verified.payload;

    // Process the request
    const result = {
      success: true,
      data: processData(payload),
      timestamp: new Date().toISOString()
    };

    // Manually sign the response
    const signedResponse = await jacs.signResponse(result);
    res.type('text/plain').send(signedResponse);

  } catch (error) {
    console.error('JACS verification failed:', error);
    res.status(400).send('Invalid JACS request');
  }
});
```

## Koa Server

### Using Koa Middleware

```javascript
import Koa from 'koa';
import { JACSKoaMiddleware } from '@hai.ai/jacs/http';

const app = new Koa();
const PORT = 3000;

// Apply JACS Koa middleware
// Handles raw body reading, verification, and response signing
app.use(JACSKoaMiddleware({
  configPath: './jacs.server.config.json'
}));

// Route handler
app.use(async (ctx) => {
  if (ctx.path === '/api/echo' && ctx.method === 'POST') {
    // Access verified payload from ctx.state.jacsPayload or ctx.jacsPayload
    const payload = ctx.state.jacsPayload || ctx.jacsPayload;

    if (!payload) {
      ctx.status = 400;
      ctx.body = 'JACS payload missing';
      return;
    }

    console.log('Received verified payload:', payload);

    // Set response object - middleware will sign it automatically
    ctx.body = {
      echo: "Koa server says hello!",
      received: payload,
      timestamp: new Date().toISOString()
    };
  } else {
    ctx.status = 404;
    ctx.body = 'Not Found. Try POST to /api/echo';
  }
});

app.listen(PORT, () => {
  console.log(`JACS Koa server listening on port ${PORT}`);
});
```

## API Reference

### jacs.signRequest(payload)

Sign an object as a JACS request.

This is a generic signed document, not a request-bound HTTP credential. Use
`JacsSimpleAgent.buildAuthHeader(...)` for authorization.

```javascript
const signedRequest = await jacs.signRequest({
  method: 'getData',
  params: { id: 123 }
});
// Returns: JACS-signed JSON string
```

### jacs.verifyResponse(responseString)

Verify a JACS-signed response and extract the payload.

This is legacy generic-document verification, not strict v2 event unwrapping.
Use `JacsSimpleAgent.unwrapSignedEvent(...)` with pinned server keys.

```javascript
const result = await jacs.verifyResponse(jacsResponseString);
// Returns: { payload: {...}, jacsId: '...', ... }

const payload = result.payload;
```

### jacs.signResponse(payload)

Sign an object as a JACS response.

For the fully bound `2.0.0` response envelope, call the instance method on
`JacsSimpleAgent`; verify it with `unwrapSignedEvent()` rather than parsing data
after an error.

```javascript
const signedResponse = await jacs.signResponse({
  success: true,
  data: { result: 42 }
});
// Returns: JACS-signed JSON string
```

### JACSExpressMiddleware(options)

Express middleware for JACS request/response handling.

```javascript
import { JACSExpressMiddleware } from '@hai.ai/jacs/http';

app.use(JACSExpressMiddleware({
  configPath: './jacs.config.json'  // Required
}));
```

**Request Processing:**
- Reads `req.body` as a JACS string
- Verifies the signature
- Attaches payload to `req.jacsPayload`
- On failure, sends 400 response

**Response Processing:**
- Intercepts `res.send()` calls
- If body is an object, signs it as JACS
- Sends signed string to client

### JACSKoaMiddleware(options)

Koa middleware for JACS request/response handling.

```javascript
import { JACSKoaMiddleware } from '@hai.ai/jacs/http';

app.use(JACSKoaMiddleware({
  configPath: './jacs.config.json'  // Required
}));
```

**Request Processing:**
- Reads raw request body
- Verifies JACS signature
- Attaches payload to `ctx.state.jacsPayload` and `ctx.jacsPayload`

**Response Processing:**
- Signs `ctx.body` if it's an object
- Converts to JACS string before sending

## Complete Example

### Server (server.js)

```javascript
import express from 'express';
import { JACSExpressMiddleware } from '@hai.ai/jacs/http';

const app = express();

// JACS middleware for /api routes
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({
  configPath: './jacs.server.config.json'
}));

// Echo endpoint
app.post('/api/echo', (req, res) => {
  const payload = req.jacsPayload;
  res.send({
    echo: payload,
    serverTime: new Date().toISOString()
  });
});

// Calculate endpoint
app.post('/api/calculate', (req, res) => {
  const { operation, a, b } = req.jacsPayload;

  let result;
  switch (operation) {
    case 'add': result = a + b; break;
    case 'subtract': result = a - b; break;
    case 'multiply': result = a * b; break;
    case 'divide': result = a / b; break;
    default: return res.status(400).send({ error: 'Unknown operation' });
  }

  res.send({ operation, a, b, result });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

### Client (client.js)

```javascript
import jacs from '@hai.ai/jacs';

async function main() {
  await jacs.load('./jacs.client.config.json');

  // Call echo endpoint
  const echoResult = await callApi('/api/echo', {
    message: 'Hello, server!'
  });
  console.log('Echo result:', echoResult);

  // Call calculate endpoint
  const calcResult = await callApi('/api/calculate', {
    operation: 'multiply',
    a: 7,
    b: 6
  });
  console.log('Calculate result:', calcResult);
}

async function callApi(path, payload) {
  const signedRequest = await jacs.signRequest(payload);

  const response = await fetch(`http://localhost:3000${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: signedRequest
  });

  const responseText = await response.text();
  const verified = await jacs.verifyResponse(responseText);
  return verified.payload;
}

main().catch(console.error);
```

## Security Considerations

### Content-Type

JACS requests should use `text/plain` content type since they are signed JSON strings, not raw JSON.

### Error Handling

Always handle verification failures gracefully:

```javascript
try {
  const verified = await jacs.verifyResponse(responseText);
  return verified.payload;
} catch (error) {
  console.error('JACS verification failed:', error.message);
  // Handle invalid/tampered response
}
```

### Agent Keys

Each server and client needs its own JACS agent with:
- Unique agent ID
- Private/public key pair
- Configuration file pointing to the keys

### Middleware Order

For Express, ensure `express.text()` comes **before** `JACSExpressMiddleware`:

```javascript
// Correct order
app.use('/api', express.text({ type: '*/*' }));
app.use('/api', JACSExpressMiddleware({ configPath: '...' }));

// Wrong - JACS middleware won't receive string body
app.use('/api', JACSExpressMiddleware({ configPath: '...' }));
app.use('/api', express.text({ type: '*/*' }));
```

## Next Steps

- [Express Middleware](express.md) - More Express integration patterns
- [MCP Integration](mcp.md) - Model Context Protocol support
- [API Reference](api.md) - Complete API documentation
