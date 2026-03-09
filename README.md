# JACS

**Prove who said what, cryptographically.**

Cryptographic signatures for AI agent outputs. No server. No account. Three lines of code.

`pip install jacs` | `npm install @hai.ai/jacs` | `cargo install jacs-cli`

> For a higher-level agent framework built on JACS, see [haiai](https://github.com/HumanAssisted/haiai).

## Quick Start

### Password Setup

```bash
export JACS_PRIVATE_KEY_PASSWORD='use-a-strong-password'
```

### Python

```python
import jacs.simple as jacs

info = jacs.quickstart(name="payments-agent", domain="payments.example.com")
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

### Node.js

```javascript
const jacs = require('@hai.ai/jacs/simple');

const info = await jacs.quickstart({
  name: 'payments-agent',
  domain: 'payments.example.com',
});
const signed = await jacs.signMessage({ action: 'approve', amount: 100 });
const result = await jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Rust / CLI

```bash
cargo install jacs-cli
jacs quickstart --name payments-agent --domain payments.example.com
jacs document create -f mydata.json
jacs verify signed-document.json
```

### Homebrew (macOS)

```bash
brew tap HumanAssisted/homebrew-jacs
brew install jacs
```

## Verify a Signed Document

No agent needed. One command or one function call.

```bash
jacs verify signed-document.json                              # exit code 0 = valid
jacs verify --remote https://example.com/doc.json --json      # fetch + verify
```

```python
result = jacs.verify_standalone(signed_json, key_directory="./keys")
```

```typescript
const r = verifyStandalone(signedJson, { keyDirectory: './keys' });
```

## When You DON'T Need JACS

- **Single developer, single service.** Standard logging is fine.
- **Internal-only prototypes.** No trust boundaries, no value in signing.
- **Simple checksums.** If you only need to detect accidental corruption, use SHA-256.

JACS adds value when data crosses trust boundaries -- between organizations, between services with different operators, or into regulated audit trails.

## Learn More

### Storage

The default storage backend is **filesystem** (keys and documents on disk). For indexed queries, **SQLite** is the recommended second option. Additional backends (DuckDB, Redb, SurrealDB) are available as experimental Cargo feature flags.

### Integrations (Experimental)

Framework adapters are available but considered experimental:

| Integration | Import | Status |
|-------------|--------|--------|
| Python + LangChain | `from jacs.adapters.langchain import jacs_signing_middleware` | Experimental |
| Python + CrewAI | `from jacs.adapters.crewai import jacs_guardrail` | Experimental |
| Python + FastAPI | `from jacs.adapters.fastapi import JacsMiddleware` | Experimental |
| Node.js + Vercel AI SDK | `require('@hai.ai/jacs/vercel-ai')` | Experimental |
| MCP (Rust, canonical) | `jacs mcp` | Stable |
| A2A Protocol | `client.get_a2a()` | Experimental |
| Go bindings | `jacsgo` | Experimental |

### Features

- **Post-quantum ready** -- ML-DSA-87 (FIPS-204) is the default algorithm alongside Ed25519 and RSA-PSS.
- **Cross-language** -- Sign in Rust, verify in Python or Node.js. Tested on every commit.
- **Multi-agent agreements** -- Quorum signing, timeouts, algorithm requirements.
- **A2A interoperability** -- Every JACS agent is an A2A agent with zero additional config.
- **Trust policies** -- `open`, `verified` (default), or `strict` modes.

### Links

- [Documentation](https://humanassisted.github.io/JACS/)
- [Full Quick Start Guide](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Algorithm Guide](https://humanassisted.github.io/JACS/advanced/algorithm-guide.html)
- [API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)
- [Use Cases](USECASES.md)

---

v0.9.3 | [Apache-2.0 OR MIT](./LICENSE-APACHE) | [Third-Party Notices](./THIRD-PARTY-NOTICES)
