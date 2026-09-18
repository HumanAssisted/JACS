import Koa from 'koa';
import { JACSKoaMiddleware } from '../http.js'; // Assuming http.js is in parent directory

const app = new Koa();
const PORT = 3001; // Port for Koa server

// Apply JACS Koa Middleware
// It handles raw body reading, JACS verification, and JACS response signing.
app.use(JACSKoaMiddleware({ configPath: './jacs.server.config.json' }));

// Route Handler
app.use(async (ctx) => {
  if (ctx.path === '/jacs-echo' && ctx.method === 'POST') {
    // Access the verified JACS payload from ctx.state.jacsPayload or ctx.jacsPayload
    const requestPayload = ctx.state.jacsPayload || ctx.jacsPayload; 
    console.log(`Koa Server: Received verified JACS payload:`, requestPayload);

    if (!requestPayload) {
        ctx.status = 400;
        ctx.body = "JACS payload missing after verification.";
        return;
    }

    const responsePayloadObject = {
      echo: "Koa server says hello!",
      received_payload: requestPayload,
      server_timestamp: new Date().toISOString()
    };

    // Set the object to be signed onto ctx.body.
    // JACSKoaMiddleware will automatically sign this before sending.
    ctx.body = responsePayloadObject;
  } else {
    ctx.status = 404;
    ctx.body = 'Not Found. Try POST to /jacs-echo';
  }
});

app.listen(PORT, () => {
  console.log(`Koa server with JACS middleware listening on http://localhost:${PORT}`);
});
