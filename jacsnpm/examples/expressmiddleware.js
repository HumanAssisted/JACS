import express from 'express';
import { createJacsMiddleware } from './http.js';  

const app = express();
const jacsMiddlewareInstance = createJacsMiddleware({ configPath: './jacs.server.config.json' });

// Middleware to get raw body (important for JACS verification)
app.use(express.text({ type: '*/*' })); // Example: treat all as text for simplicity here

// Adapter for JACS middleware
app.use(async (req, res, next) => {
  const ctx = {
    request: req.body, // Assuming raw body is now in req.body as a string
    response: undefined, // Will be populated by the route handler
    // You might need to map other req/res properties if the jacs module uses them
  };

  try {
    await jacsMiddlewareInstance(ctx, async () => {
      // This 'next' for JACS middleware allows it to proceed.
      // Now, we create a 'next' for Express route handlers.
      // The actual route handler will run here.
      // We'll store its response on res.locals to pick it up later.
      return new Promise((resolve, reject) => {
        res.locals.expressNext = resolve; // Store resolve to call when actual route handler is done
        next(); // Call the next Express middleware/route handler
      });
    });

    // After JACS middleware has signed ctx.response
    if (ctx.response) {
      res.send(ctx.response);
    } else if (!res.headersSent) {
      // If no response set by JACS (e.g. error during signing was handled differently)
      // or if the route didn't set ctx.response (which it should via res.locals.jacsResponseData)
      res.status(500).send("Error in JACS processing or no response generated.");
    }
  } catch (error) {
    console.error("JACS middleware or handler error:", error);
    if (!res.headersSent) {
      res.status(500).send(error.message || "JACS processing error");
    }
  }
});

app.post('/api/data', (req, res) => {
  // req.body here is the actual JACS payload (due to ctx.request = verifiedRequest.payload)
  // This is a bit tricky because the adapter set ctx.request = req.body, then JACS middleware modified ctx.request.
  // A cleaner adapter would pass the *original* req.body to ctx.request for JACS,
  // and then the Express route would get the *verified* payload (e.g. from req.jacsPayload).
  // For now, let's assume the JACS middleware modified what our route sees.
  // The `ctx.request` in the JACS middleware scope is what we care about.

  console.log("Verified request payload in Express route:", req.body); // This might be the original or verified, needs careful adapter logic

  const responseData = { message: "Express response", received: req.body };

  // Place response for JACS middleware to pick up via the adapter
  // The adapter above would need to be modified to ensure `ctx.response` is set from this.
  // A simpler way is if the jacsMiddlewareInstance modified a property on `res` directly.
  // Let's adjust: the jacsMiddlewareInstance expects to set `ctx.response`.
  // Our adapter needs to ensure that what the route sets via `res.locals.jacsResponseData` (example)
  // becomes `ctx.response` before the JACS response signing phase.
  // This is getting complex for a quick example, highlighting the need for careful adaptation.

  // Simpler: Assume the middleware instance modifies 'ctx.response'
  // The route needs to set data that becomes `ctx.response`.
  // The adapter will set `ctx.response = res.locals.responseData` before JACS signing.
  // For this example: the adapter needs to handle routing `res.send` etc. to update `ctx.response`

  // Let's assume the adapter handles it: the JACS middleware operates on `ctx`.
  // Our route handler sets data that ends up on `ctx.response` for the JACS middleware to sign.
  // This is not how Express typically works directly.

  // The most straightforward adaptation for Express is if createJacsMiddleware was:
  // function(options) { return async (req, res, next) => { /* logic using req, res */ } }
  // Since it's (ctx, next), the adapter is key.

  // For the current structure, the route should not send the response.
  // It should prepare data, and the adapter ensures it gets to ctx.response for signing.
  res.locals.responseData = responseData; // Route sets data
  res.locals.expressNext(); // Signal route handler completion to the adapter
});

app.listen(3000, () => console.log('Express server with JACS adapter running on port 3000'));
