# JACS

**Sign it. Prove it.** -- Agent trust infrastructure for a world where AI agents cross organizational boundaries.

Cryptographic signatures for AI agent outputs so anyone can verify who said what, whether it was changed, and hold agents accountable. No server. No account. Three lines of code.

`pip install jacs` | `npm install @hai.ai/jacs` | `cargo install jacs`

## Quick Start

Zero-config -- one call creates a persistent agent with keys on disk.

### Python

```python
import jacs.simple as jacs

jacs.quickstart()
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

### Node.js

```javascript
const jacs = require('@hai.ai/jacs/simple');

async function main() {
  await jacs.quickstart();
  const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
  const result = await jacs.verify(signed.raw);
  console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
}

main().catch(console.error);
```

### Rust / CLI

```bash
# Install from source (requires Rust toolchain)
cargo install jacs --features cli

# Or download a prebuilt binary from GitHub Releases
# https://github.com/HumanAssisted/JACS/releases

jacs quickstart
jacs document create -f mydata.json
```

**Signed your first document?** Next: [Verify it without an agent](#verify-a-signed-document) | [Pick your framework integration](#which-integration-should-i-use) | [Full quick start guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Verify a Signed Document

No agent needed. One command or one function call.

```bash
jacs verify signed-document.json          # CLI -- exit code 0 = valid
jacs verify --remote https://example.com/doc.json --json   # fetch + verify
```

```python
result = jacs.verify_standalone(signed_json, key_directory="./keys")  # Python, no agent
```

```typescript
const r = verifyStandalone(signedJson, { keyDirectory: './keys' });   // Node.js, no agent
```

[Full verification guide](https://humanassisted.github.io/JACS/getting-started/verification.html) -- CLI, Python, Node.js, DNS, verification links.

## Which Integration Should I Use?

Find the right path in under 2 minutes. [Full decision tree](https://humanassisted.github.io/JACS/getting-started/decision-tree.html)

| I use... | Start here | Docs |
|----------|-----------|------|
| Python + LangChain/LangGraph | `from jacs.adapters.langchain import jacs_signing_middleware` | [LangChain Guide](https://humanassisted.github.io/JACS/python/adapters.html) |
| Python + CrewAI | `from jacs.adapters.crewai import jacs_guardrail` | [CrewAI Guide](https://humanassisted.github.io/JACS/python/adapters.html) |
| Python + FastAPI | `from jacs.adapters.fastapi import JacsMiddleware` | [FastAPI Guide](https://humanassisted.github.io/JACS/python/adapters.html) |
| Node.js + Express | `require('@hai.ai/jacs/express')` | [Express Guide](https://humanassisted.github.io/JACS/nodejs/express.html) |
| Node.js + Vercel AI SDK | `require('@hai.ai/jacs/vercel-ai')` | [Vercel AI Guide](https://humanassisted.github.io/JACS/nodejs/vercel-ai.html) |
| Node.js + LangChain.js | `require('@hai.ai/jacs/langchain')` | [LangChain.js Guide](https://humanassisted.github.io/JACS/nodejs/langchain.html) |
| MCP Server (Python) | `from jacs.mcp import create_jacs_mcp_server` | [Python MCP Guide](https://humanassisted.github.io/JACS/python/mcp.html) |
| MCP Server (Node.js) | `require('@hai.ai/jacs/mcp')` | [Node.js MCP Guide](https://humanassisted.github.io/JACS/nodejs/mcp.html) |
| A2A Protocol | `from jacs.a2a import JACSA2AIntegration` | [A2A Guide](https://humanassisted.github.io/JACS/integrations/a2a.html) |
| Rust / CLI | `cargo install jacs --features cli` | [Rust Guide](https://humanassisted.github.io/JACS/rust/installation.html) |
| Any language (standalone) | `import jacs.simple as jacs` | [Simple API](https://humanassisted.github.io/JACS/python/simple-api.html) |

## Who Is JACS For?

**Platform teams** building multi-agent systems where agents from different services -- or different organizations -- need to trust each other's outputs.

**Compliance and security engineers** in regulated industries (finance, healthcare, government) who need cryptographic proof of agent actions, not just log files.

**AI framework developers** adding provenance to LangChain, CrewAI, FastAPI, Express, Vercel AI, or MCP pipelines without changing their existing architecture.

**Researchers and labs** running public-facing agents that need verifiable identity without exposing operator information.

## When You DON'T Need JACS

Honesty builds trust, so here is when JACS is probably overkill:

- **Single developer, single service.** If all your agents run inside one process you control and you trust your own logs, standard logging is fine.
- **Internal-only prototypes.** If data never leaves your organization and you are not in a regulated environment, the overhead of cryptographic signing adds no value yet.
- **Simple checksums.** If you only need to detect accidental corruption (not prove authorship), SHA-256 hashes are simpler.

JACS adds value when data crosses trust boundaries -- between organizations, between services with different operators, or into regulated audit trails.

## The Trust Blind Spot

A 2026 survey of 29 multi-agent reinforcement learning publications found that **zero** addressed authentication, integrity, or trust between agents (Wittner, "Communication Methods in Multi-Agent RL," [arxiv.org/abs/2601.12886](https://arxiv.org/abs/2601.12886)). Every paper optimized for communication efficiency while assuming a fully trusted environment.

That assumption holds in a research lab. It does not hold in production, where agents cross organizational boundaries, outputs are consumed by downstream systems, and regulatory auditors expect cryptographic proof.

JACS provides the missing trust layer: identity (who produced this?), integrity (was it changed?), and accountability (can you prove it?).

## Post-Quantum Ready

JACS supports ML-DSA-87 (FIPS-204) post-quantum signatures alongside classical algorithms (Ed25519, ECDSA P-256/P-384, RSA-PSS). The `pq2025` algorithm preset gives you quantum-resistant signing today, with zero code changes from the standard API.

[Algorithm Selection Guide](https://humanassisted.github.io/JACS/advanced/algorithm-guide.html)

## Cross-Language Compatibility

A document signed by a Rust agent can be verified by a Python or Node.js agent, and vice versa. The signature format is language-agnostic -- any JACS binding produces and consumes the same signed JSON.

Cross-language interoperability is tested on every commit with both Ed25519 and post-quantum (ML-DSA-87) algorithms. Rust generates signed fixtures, then Python and Node.js verify and countersign them. See the test suites: [`jacs/tests/cross_language/`](jacs/tests/cross_language/mod.rs), [`jacspy/tests/test_cross_language.py`](jacspy/tests/test_cross_language.py), [`jacsnpm/test/cross-language.test.js`](jacsnpm/test/cross-language.test.js).

## Use Cases

**Prove that pipeline outputs are authentic.** A build service signs every JSON artifact it emits. Downstream teams and auditors verify with a single call; tampering or forgery is caught immediately. [Full scenario](USECASES.md#1-verifying-that-json-files-came-from-a-specific-program)

**Run a public agent without exposing the operator.** An AI agent signs every message but only publishes the public key via DNS or HAI. Recipients verify origin and integrity cryptographically; the operator's identity never touches the internet. [Full scenario](USECASES.md#2-protecting-your-agents-identity-on-the-internet)

**Add cryptographic provenance in any language.** Finance, healthcare, or any regulated environment: sign every output with `sign_message()`, verify with `verify()`. The same three-line pattern works identically in Python, Node.js, Rust, and Go. [Full scenario](USECASES.md#4-a-go-node-or-python-agent-with-strong-data-provenance)

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Decision Tree](https://humanassisted.github.io/JACS/getting-started/decision-tree.html)
- [Algorithm Guide](https://humanassisted.github.io/JACS/advanced/algorithm-guide.html)
- [API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)

---

v0.8.0 | [Apache 2.0 with Common Clause](./LICENSE) | [hai.ai](https://hai.ai)
