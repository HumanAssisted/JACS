import Koa from 'koa';
import { createJacsMiddleware } from '../http.js';

const app = new Koa();
const PORT = 3001; // Port for Koa server

// 1. Middleware to get raw body and place it on ctx.request for JACS middleware
app.use(async (ctx, next) => {
  if (ctx.request.method === 'POST' || ctx.request.method === 'PUT') {
    try {
      const body = await new Promise((resolve, reject) => {
        let data = '';
        ctx.req.on('data', chunk => data += chunk);
        ctx.req.on('end', () => resolve(data));
        ctx.req.on('error', err => reject(err));
      });
      // IMPORTANT: createJacsMiddleware expects the JACS string to BE ctx.request
      ctx.request = body;
    } catch (err) {
      console.error("Error reading raw body for Koa:", err);
      ctx.throw(400, 'Failed to read request body');
      return; // Stop processing if body read fails
    }
  }
  await next();
});

// 2. JACS Middleware
// The createJacsMiddleware itself loads the jacs NAPI and its config.
const jacsKoaMiddleware = createJacsMiddleware({ configPath: './jacs.server.config.json' });
app.use(jacsKoaMiddleware);

// 3. Route Handler
app.use(async (ctx) => {
  if (ctx.path === '/jacs-echo' && ctx.method === 'POST') {
    // After JACS middleware, ctx.request is the *verified payload* (object)
    const requestPayload = ctx.request;
    console.log(`Koa Server: Received verified payload:`, requestPayload);

    const responsePayload = {
      echo: "Koa server says hello!",
      received_payload: requestPayload,
      server_timestamp: new Date().toISOString()
    };

    // This will be picked up by createJacsMiddleware to be signed
    ctx.response.type = 'text/plain'; // JACS middleware will output a JACS string.
                                     // The actual Content-Type of the JACS string itself might be different.
    ctx.response.body = responsePayload; // This is what JACS middleware's `ctx.response` will see.
  } else {
    ctx.response.status = 404;
    ctx.response.body = 'Not Found. Try POST to /jacs-echo';
  }
});

app.listen(PORT, () => {
  console.log(`Koa server with JACS middleware listening on http://localhost:${PORT}`);
});
