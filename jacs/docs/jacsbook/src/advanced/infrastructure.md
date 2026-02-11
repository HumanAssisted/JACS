# Infrastructure vs Tools: JACS as Middleware

Most signing libraries work as **tools**: the developer calls `sign()` and `verify()` manually at each point where integrity matters. JACS can work that way too, but its real value appears when it operates as **infrastructure** -- signing happens automatically as a side effect of normal framework usage.

## The difference

| Approach | Developer effort | Coverage |
|----------|-----------------|----------|
| **Tool** | Call `sign()`/`verify()` at every boundary | Only where you remember to add it |
| **Infrastructure** | Add 1-3 lines of setup | Every request/response automatically |

## Transport-level: MCP proxies

JACS MCP transport proxies sit between client and server. Every JSON-RPC message is signed on the way out and verified on the way in. The MCP tools themselves never call a signing function -- it happens at the transport layer.

```
Client --> [JACS Proxy: sign] --> Server
Client <-- [JACS Proxy: verify] <-- Server
```

No application code changes. The proxy handles it.

## Framework-level: Express / FastAPI middleware

A single middleware line signs every HTTP response automatically:

```python
# FastAPI -- one line of setup
app.add_middleware(JacsMiddleware, client=jacs_client)
# Every response now carries a JACS signature header
```

```typescript
// Express -- one line of setup
app.use(jacsMiddleware({ client }));
// Every response now carries a JACS signature header
```

The route handlers are unchanged. Signing is invisible to the developer writing business logic.

## Protocol-level: A2A agent cards

When JACS publishes an A2A agent card, the card includes the agent's public key and supported algorithms. Any other A2A-compatible agent can verify signatures without prior arrangement -- the trust bootstrapping is built into the protocol.

## Why this matters

Manual signing has the same problem as manual memory management: developers forget, and the places they forget are the places attackers target. Infrastructure-level signing eliminates that gap.

- **MCP transport**: every tool call and result is signed, not just the ones you thought to protect
- **HTTP middleware**: every API response is signed, including error responses and health checks
- **A2A integration**: every agent interaction is verifiable, including discovery

The developer adds setup code once. After that, signing happens everywhere automatically -- including in code paths the developer never explicitly considered.

## When to use each approach

Use JACS as a **tool** when you need fine-grained control: signing specific documents, creating agreements between named parties, or building custom verification workflows.

Use JACS as **infrastructure** when you want blanket coverage: every message signed, every response verifiable, every agent interaction auditable. This is the recommended default for production deployments.

Both approaches use the same keys, the same signatures, and the same verification. The difference is who calls `sign()` -- you, or the framework.
