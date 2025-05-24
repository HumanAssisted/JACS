import express from 'express';
import { JACSExpressMiddleware } from '../http.js'; // Assuming http.js is in parent directory

const app = express();
const PORT = 3002;

// 1. Middleware to get raw body as text for JACS processing
// IMPORTANT: This MUST come before JACSExpressMiddleware for routes that need JACS.
app.use('/jacs-echo', express.text({ type: '*/*' })); // Ensures req.body is a string for JACS

// 2. Apply JACS Express Middleware
// It expects req.body to be a string (from express.text), handles JACS verification,
// and wraps res.send() to automatically sign object responses.
app.use('/jacs-echo', JACSExpressMiddleware({ configPath: './jacs.server.config.json' }));

// 3. Route Handler
app.post('/jacs-echo', (req, res) => {
  // Access the verified JACS payload from req.jacsPayload
  const requestPayload = req.jacsPayload;
  console.log(`Express Server: Received verified JACS payload:`, requestPayload);

  if (!requestPayload) {
      // This case should ideally be handled by JACSExpressMiddleware sending a 400
      // if JACS verification failed or no payload was derived.
      return res.status(400).send("JACS payload missing after verification.");
  }

  const responsePayloadObject = {
    echo: "Express server says hello!",
    received_payload: requestPayload,
    server_timestamp: new Date().toISOString()
  };

  // Send the object. JACSExpressMiddleware will intercept this call to res.send(),
  // sign the object, and then send the actual JACS string.
  res.send(responsePayloadObject);
});

// Fallback for other routes
app.use((req, res) => {
  res.status(404).send('Not Found. Try POST to /jacs-echo');
});

app.listen(PORT, () => {
  console.log(`Express server with JACS middleware listening on http://localhost:${PORT}`);
});
