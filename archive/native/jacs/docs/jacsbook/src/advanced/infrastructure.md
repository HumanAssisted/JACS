# Signing at Integration Boundaries

Use explicit signing calls for selected artifacts, or an adapter to apply signing at a framework boundary. Adapters cover their documented message/body types; they do not guarantee that every application path is signed or authorized.

## MCP transports

The ready-made Rust server exposes ordinary MCP tools to standard clients. Node/Python signed transport wrappers instead require a matching JACS wrapper at both endpoints, trusted peer keys and expected identities. They sign custom carriers over supported local transports; they do not encrypt them. See [MCP integration](../integrations/mcp.md).

## HTTP middleware

Express, Koa and FastAPI adapters sign or inspect supported document bodies. Coverage differs by adapter: FastAPI's request verifier handles signed JSON objects on POST, while unsigned/non-JSON bodies and other methods can reach the application even with strict mode. Do not treat middleware installation as caller authentication or route authorization.

For request-bound authentication, bind method, URL, exact body bytes and audience, verify under independently trusted keys, enforce replay protection and apply application policy. See [HTTP protocol](../nodejs/http.md), [Express](../nodejs/express.md), [Koa](../nodejs/koa.md) and [Python adapters](../python/adapters.md).

## A2A discovery

JACS publishes signed cards and public evidence using a persisted native PQ root or explicit ES256 compatibility. Peers need support for the chosen algorithm and independently trusted key selection. Discovery routers do not implement advertised message/task handlers or grant permission to call them. Follow the [A2A how-to](https://humanassisted.github.io/JACS/a2a.html).

Choose the integration that covers the actual boundary, then test unsigned, malformed and unauthorized input as well as successful signing. Signature validity establishes integrity under a key; the host owns identity attribution, claim evaluation and authorization.
