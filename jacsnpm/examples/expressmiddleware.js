/**
 * Express Middleware Example — JACS v0.8.0
 *
 * Demonstrates the new jacsMiddleware() from @hai.ai/jacs/express.
 * Verifies incoming signed requests and provides req.jacsClient
 * for manual signing in route handlers.
 *
 * Usage:
 *   npm install express
 *   node expressmiddleware.js
 */
import express from 'express';
import { JacsClient } from '../client.js';
import { jacsMiddleware } from '../express.js';

const app = express();
const PORT = 3002;

async function main() {
  // Initialize JACS client once
  const client = await JacsClient.quickstart();

  // Parse bodies as text so JACS can verify the raw signed document
  app.use('/api', express.text({ type: '*/*' }));

  // Apply JACS middleware — verifies incoming, exposes req.jacsClient
  app.use('/api', jacsMiddleware({ client, verify: true }));

  // Echo route: verifies incoming, manually signs response
  app.post('/api/echo', async (req, res) => {
    const payload = req.jacsPayload;
    if (!payload) {
      return res.status(400).json({ error: 'No verified payload' });
    }

    console.log('Verified payload:', payload);

    // Sign and send response using req.jacsClient
    const signed = await req.jacsClient.signMessage({
      echo: 'Hello from Express!',
      received: payload,
      timestamp: new Date().toISOString(),
    });
    res.type('text/plain').send(signed.raw);
  });

  // Health check (no JACS)
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  app.listen(PORT, () => {
    console.log(`Express + JACS listening on http://localhost:${PORT}`);
    console.log('POST /api/echo with a JACS-signed body to test');
  });
}

main().catch(console.error);
