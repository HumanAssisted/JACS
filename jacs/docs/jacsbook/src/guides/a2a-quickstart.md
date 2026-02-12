# A2A Quickstart

Three focused mini-guides to get your JACS agent working with A2A.

| Guide | What You'll Do | Time |
|-------|---------------|------|
| **[1. Serve](a2a-serve.md)** | Publish your Agent Card so other agents can find you | 2 min |
| **[2. Discover & Trust](a2a-discover.md)** | Find remote agents and assess their trustworthiness | 2 min |
| **[3. Exchange](a2a-exchange.md)** | Sign and verify A2A artifacts with chain of custody | 3 min |

> **Single-page version:** See the [A2A Quick Start](../../../../A2A_QUICKSTART.md) at the repo root for a 10-line journey.

---

## JACS for A2A Developers

Already using Google's A2A protocol? Here's what JACS adds -- and what stays the same.

### What Stays the Same

- **Agent Cards** follow the v0.4.0 shape. Your existing Agent Card fields (`name`, `description`, `skills`, `url`) are preserved.
- **Discovery** uses `/.well-known/agent-card.json`. No new endpoints are required for basic interop.
- **JSON-RPC** transport is untouched. JACS works alongside A2A, not instead of it.

### What JACS Adds

| A2A Alone | With JACS |
|-----------|-----------|
| Agent Card has no signature | Agent Card is JWS-signed + JWKS published |
| Artifacts are unsigned payloads | Artifacts carry `jacsSignature` with signer ID, algorithm, and timestamp |
| Trust is transport-level (TLS) | Trust is data-level -- signatures persist offline |
| No chain of custody | `parent_signatures` link artifacts into a verifiable chain |
| No standard trust policy | `open` / `verified` / `strict` policies built in |

### Minimal Integration (Add JACS to Existing A2A Code)

If you already serve an Agent Card, adding JACS provenance takes two steps:

**Step 1:** Add the JACS extension to your Agent Card's `capabilities`:

```json
{
  "capabilities": {
    "extensions": [{
      "uri": "urn:hai.ai:jacs-provenance-v1",
      "description": "JACS cryptographic document signing",
      "required": false
    }]
  }
}
```

**Step 2:** Sign artifacts before sending them:

```python
from jacs.client import JacsClient

client = JacsClient.quickstart()
# Wrap your existing artifact payload
signed = client.sign_artifact(your_existing_artifact, "task")
# Send `signed` instead of the raw artifact
```

Receiving agents that don't understand JACS will ignore the extra fields. Receiving agents that do understand JACS can verify the signature and assess trust.

### Dual Key Architecture

JACS generates two key pairs per agent:

- **Post-quantum (ML-DSA-87)** for JACS document signatures -- future-proof
- **Traditional (RSA/ECDSA)** for JWS Agent Card signatures -- A2A ecosystem compatibility

This means your agent is compatible with both the current A2A ecosystem and quantum-resistant verification.

---

## Troubleshooting FAQ

**Q: `pip install jacs[a2a-server]` fails.**
A: The `a2a-server` extra requires Python 3.10+ and adds FastAPI + uvicorn. If you only need signing (not serving), use `pip install jacs` with no extras.

**Q: `discover_and_assess` returns `jacs_registered: false`.**
A: The remote agent's Agent Card does not include the `urn:hai.ai:jacs-provenance-v1` extension. This is normal for non-JACS A2A agents. With the `open` trust policy, they are still allowed; with `verified`, they are rejected.

**Q: Verification returns `valid: true` but `trust.allowed: false`.**
A: The signature is cryptographically correct, but the trust policy rejected the signer. With `strict` policy, the signer must be in your local trust store. Add them with `a2a.trust_a2a_agent(card_json)`.

**Q: `sign_artifact` raises "no agent loaded".**
A: Call `JacsClient.quickstart()` or `JacsClient(config_path=...)` before signing. The client must have a loaded agent with keys.

**Q: Agent Card export returns empty skills.**
A: Skills are derived from `jacsServices` in the agent definition. Pass `skills=[...]` to `export_agent_card()` to override, or define services when creating the agent.

**Q: My existing A2A client doesn't understand the JACS fields.**
A: This is expected. JACS fields (`jacsId`, `jacsSignature`, `jacsSha256`) are additive. Non-JACS clients should ignore unknown fields per JSON convention. If a client rejects them, strip JACS fields before sending by extracting `signed["payload"]`.

**Q: How do I verify artifacts from agents I've never seen before?**
A: Use `JACS_KEY_RESOLUTION` to configure key lookup. Set `JACS_KEY_RESOLUTION=local,hai` to check your local cache first, then the HAI key service. For offline-only verification, set `JACS_KEY_RESOLUTION=local`.

---

## Next Steps

- **[A2A Interoperability Reference](../integrations/a2a.md)** -- Full API reference, well-known documents, MCP integration
- **[Trust Store](../advanced/trust-store.md)** -- Managing trusted agents
- **[Express Middleware](../nodejs/express.md)** -- Add A2A to existing Express apps
- **[Framework Adapters](../python/adapters.md)** -- Auto-sign with LangChain, FastAPI, CrewAI
- **[Observability & Monitoring Guide](observability.md)** -- Monitor signing and verification events
- **[Hero Demo (Python)](https://github.com/HumanAssisted/JACS/blob/main/examples/a2a_trust_demo.py)** -- 3-agent trust verification example
- **[Hero Demo (Node.js)](https://github.com/HumanAssisted/JACS/blob/main/examples/a2a_trust_demo.ts)** -- Same demo in TypeScript
