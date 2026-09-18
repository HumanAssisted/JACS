# Web Server Integrations

This umbrella chapter has been reduced on purpose. The old version duplicated framework docs and overstated support for stacks that are not first-class in this repo.

## Use The Language-Specific Pages Instead

- **Python FastAPI / Starlette**: [Framework Adapters](../python/adapters.md)
- **Node.js Express**: [Express Middleware](../nodejs/express.md)
- **Node.js Koa**: [Koa Middleware](../nodejs/koa.md)

## Current Support Snapshot

- FastAPI / Starlette middleware is first-class in Python via `JacsMiddleware`
- Express middleware is first-class in Node via `@hai.ai/jacs/express`
- Koa middleware is first-class in Node via `@hai.ai/jacs/koa`
- Flask is **not** a first-class adapter in this repo today

If you also need A2A discovery from a web app:

- Python: use `jacs.a2a_server` or `JacsMiddleware(..., a2a=True)`
- Node.js: use `jacsA2AMiddleware()` in an Express app
