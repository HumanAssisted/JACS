# JACS

**Sign it. Prove it.**

Cryptographic signatures for AI agent outputs -- so anyone can verify who said what and whether it was changed. No server. Three lines of code.

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

jacs.quickstart();
const signed = jacs.signMessage({ action: 'approve', amount: 100 });
const result = jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Rust / CLI

```bash
cargo install jacs --features cli
jacs quickstart
jacs document create -f mydata.json
```

## Is JACS right for you?

- **Building agents that talk to the outside world?** JACS signs their outputs so anyone can verify.
- **Running in a regulated environment?** Post-quantum signatures (ML-DSA-87 / FIPS-204), audit trails, non-repudiation.
- **Multiple agents, multiple organizations?** Signed agreements with quorum, cryptographic identity via DNS or HAI.

If all your agents run inside a single service you control and you trust your own logs, you probably don't need JACS. It adds value when data crosses trust boundaries.

[Full decision tree: which integration should I use?](https://humanassisted.github.io/JACS/getting-started/decision-tree.html)

## Use Cases

**Prove that pipeline outputs are authentic.** A build service signs every JSON artifact it emits -- deployment configs, test reports, compliance summaries. Downstream teams and auditors verify with a single call; tampering or forgery is caught immediately. [Full scenario](USECASES.md#1-verifying-that-json-files-came-from-a-specific-program)

**Run a public agent without exposing the operator.** An AI agent signs every message it sends but only publishes the public key (via DNS or HAI). Recipients verify origin and integrity cryptographically; the operator's identity never touches the internet. [Full scenario](USECASES.md#2-protecting-your-agents-identity-on-the-internet)

**Add cryptographic provenance in any language.** Finance, healthcare, or any regulated environment: sign every output with `sign_message()`, verify with `verify()`. The same three-line pattern works identically in Python, Node.js, and Go. Auditors get cryptographic proof instead of trust-only logs. [Full scenario](USECASES.md#4-a-go-node-or-python-agent-with-strong-data-provenance)

## Framework Integrations

| Framework | Python | Node.js |
|-----------|--------|---------|
| LangChain/LangGraph | `jacs.adapters.langchain` | `@hai.ai/jacs/langchain` |
| CrewAI | `jacs.adapters.crewai` | -- |
| FastAPI | `jacs.adapters.fastapi` | -- |
| Express | -- | `@hai.ai/jacs/express` |
| Vercel AI SDK | -- | `@hai.ai/jacs/vercel-ai` |
| MCP | `jacs.mcp` | `@hai.ai/jacs/mcp` |
| A2A Protocol | `jacs.a2a` | -- |

Each adapter wraps JACS signing into the framework's native patterns. [Quickstart guides](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Algorithm Guide](https://humanassisted.github.io/JACS/advanced/algorithm-guide.html)
- [API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)

---

v0.8.0 | [Apache 2.0 with Common Clause](./LICENSE) | [hai.ai](https://hai.ai)
