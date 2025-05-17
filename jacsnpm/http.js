import jacs from './index.js'; // Assuming JACS NAPI is here

/**
 * JACS Middleware for Koa.js applications.
 * Reads the raw request body, verifies JACS, makes payload available as ctx.jacsPayload.
 * Signs the response object from ctx.body before sending.
 * @param {Object} options
 * @param {string} options.configPath - Path to JACS config file for the server.
 */
export function JACSKoaMiddleware(options = {}) {
  if (!options.configPath) {
    throw new Error("JACSKoaMiddleware: options.configPath is required.");
  }

  return async (ctx, next) => {
    // Ensure JACS NAPI is loaded with the server's config
    // Consider loading this once when the middleware is initialized if jacs.load supports it,
    // or ensure jacs instance is pre-configured. For simplicity, loading per request if not cached.
    try {
      await jacs.load(options.configPath);
    } catch (loadError) {
      console.error("JACSKoaMiddleware: Failed to load JACS config:", loadError);
      ctx.status = 500;
      ctx.body = "JACS configuration error on server.";
      return;
    }

    // 1. Request Handling
    if (ctx.request.method === 'POST' || ctx.request.method === 'PUT') { // Or any method with a body
      let rawBody = '';
      try {
        const bodyBuffer = [];
        for await (const chunk of ctx.req) { // ctx.req is the Node.js incoming message
          bodyBuffer.push(chunk);
        }
        rawBody = Buffer.concat(bodyBuffer).toString();
      } catch (err) {
        console.error("JACSKoaMiddleware: Error reading raw request body:", err);
        ctx.status = 400;
        ctx.body = 'Failed to read request body.';
        return;
      }

      if (rawBody) {
        try {
          console.log("JACSKoaMiddleware: Verifying incoming JACS string...");
          const verificationResult = await jacs.verifyResponse(rawBody);
          ctx.state.jacsPayload = verificationResult.payload; // Standard place for Koa state
          ctx.jacsPayload = verificationResult.payload; // For convenience
          console.log("JACSKoaMiddleware: JACS request verified. Payload in ctx.state.jacsPayload / ctx.jacsPayload.");
        } catch (jacsError) {
          console.error("JACSKoaMiddleware: JACS verification failed:", jacsError);
          ctx.status = 400; // Bad Request - JACS validation failed
          ctx.body = `Invalid JACS request: ${jacsError.message}`;
          return;
        }
      } else {
        console.log("JACSKoaMiddleware: No body found in POST/PUT request for JACS verification.");
        // Depending on policy, might error or proceed if JACS is optional for this path
      }
    }

    await next(); // Call the next middleware (e.g., your route handler)

    // 2. Response Handling
    // Check if ctx.body is an object intended for signing (and not already a string or buffer)
    if (ctx.body && typeof ctx.body === 'object' && !(ctx.body instanceof String) && !Buffer.isBuffer(ctx.body) && !(typeof ctx.body.pipe === 'function')) {
      try {
        console.log("JACSKoaMiddleware: Signing outgoing response from ctx.body:", ctx.body);
        const jacsStringResponse = await jacs.signRequest(ctx.body);
        ctx.body = jacsStringResponse; // Replace object payload with JACS string
        ctx.type = 'text/plain';      // Set Content-Type for the JACS string
        console.log("JACSKoaMiddleware: JACS response signed.");
      } catch (jacsError) {
        console.error("JACSKoaMiddleware: Failed to sign JACS response:", jacsError);
        // Potentially overwrite ctx.body with an error or re-throw
        ctx.status = 500;
        ctx.body = `Failed to sign JACS response: ${jacsError.message}`;
      }
    }
  };
}

/**
 * JACS Middleware for Express.js applications.
 * Expects raw request body string in req.body (e.g., from express.text()).
 * Verifies JACS, makes payload available as req.jacsPayload.
 * Wraps res.send to sign the response object before sending.
 * @param {Object} options
 * @param {string} options.configPath - Path to JACS config file for the server.
 */
export function JACSExpressMiddleware(options = {}) {
  if (!options.configPath) {
    throw new Error("JACSExpressMiddleware: options.configPath is required.");
  }

  return async (req, res, next) => {
    // Ensure JACS NAPI is loaded
    try {
      await jacs.load(options.configPath);
    } catch (loadError) {
      console.error("JACSExpressMiddleware: Failed to load JACS config:", loadError);
      res.status(500).send("JACS configuration error on server.");
      return;
    }

    // 1. Request Handling
    // Assumes prior middleware (like express.text()) has put raw string body into req.body
    if ((req.method === 'POST' || req.method === 'PUT') && typeof req.body === 'string' && req.body.length > 0) {
      try {
        console.log("JACSExpressMiddleware: Verifying incoming JACS string from req.body...");
        const verificationResult = await jacs.verifyResponse(req.body);
        req.jacsPayload = verificationResult.payload;
        console.log("JACSExpressMiddleware: JACS request verified. Payload in req.jacsPayload.");
      } catch (jacsError) {
        console.error("JACSExpressMiddleware: JACS verification failed:", jacsError);
        res.status(400).send(`Invalid JACS request: ${jacsError.message}`);
        return;
      }
    } else if ((req.method === 'POST' || req.method === 'PUT') && (!req.body || typeof req.body !== 'string')) {
      console.log("JACSExpressMiddleware: req.body is not a JACS string. Ensure express.text() or similar is used before this middleware for POST/PUT.");
      // Depending on policy, you might proceed or error if JACS is mandatory
    }

    // 2. Response Handling - Wrap res.send
    const originalSend = res.send.bind(res);
    res.send = async function (body) {
      // 'this' is 'res'
      if (body && typeof body === 'object' && !(body instanceof String) && !Buffer.isBuffer(body) && !(typeof body.pipe === 'function')) {
        try {
          console.log("JACSExpressMiddleware (res.send wrapper): Signing outgoing response object:", body);
          const jacsStringResponse = await jacs.signRequest(body);
          this.type('text/plain'); // Set Content-Type for the JACS string
          console.log("JACSExpressMiddleware (res.send wrapper): JACS response signed.");
          originalSend(jacsStringResponse);
        } catch (jacsError) {
          console.error("JACSExpressMiddleware (res.send wrapper): Failed to sign JACS response:", jacsError);
          // Handle error - send an error response
          if (!this.headersSent) {
            this.status(500).type('text/plain').send(`Failed to sign JACS response: ${jacsError.message}`);
          }
        }
      } else {
        // Not an object to sign, or already a string/buffer, send as is
        originalSend(body);
      }
    };

    next(); // Call the next middleware (e.g., your route handler)
  };
}

// The old generic middleware, can be removed or kept for other purposes.
// export function createJacsMiddleware(options = {}) { ... }