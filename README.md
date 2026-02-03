# JACS

**JSON Agent Communication Standard** - Cryptographic signing and verification for AI agents.

**[Documentation](https://humanassisted.github.io/JACS/)** | **[Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)** | **[API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)**

## What is JACS?

JACS provides cryptographic signatures for AI agent communications. Every message, file, or artifact can be signed and verified, ensuring:

- **Authenticity**: Prove who created the data
- **Integrity**: Detect tampering
- **Non-repudiation**: Signed actions can't be denied

## Quick Start

### Python

```bash
pip install jacs
```

```python
from jacs import simple

# Load your agent
simple.load('./jacs.config.json')

# Sign any data
signed = simple.sign_message({'action': 'approve', 'amount': 100})

# Verify signatures
result = simple.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

### Node.js

```bash
npm install @hai-ai/jacs
```

```javascript
const jacs = require('@hai-ai/jacs/simple');

jacs.load('./jacs.config.json');

const signed = jacs.signMessage({ action: 'approve', amount: 100 });
const result = jacs.verify(signed.raw);
console.log(`Valid: ${result.valid}, Signer: ${result.signerId}`);
```

### Go

```go
import jacs "github.com/HumanAssisted/JACS/jacsgo"

jacs.Load(nil)

signed, _ := jacs.SignMessage(map[string]interface{}{"action": "approve"})
result, _ := jacs.Verify(signed.Raw)
fmt.Printf("Valid: %t, Signer: %s\n", result.Valid, result.SignerID)
```

### Rust / CLI

```bash
cargo install jacs

# Create an agent
jacs init

# Sign a document
jacs document create -f mydata.json
```

## Core API (All Languages)

| Function | Description |
|----------|-------------|
| `load(config)` | Load agent from config file |
| `sign_message(data)` | Sign any JSON data |
| `sign_file(path, embed)` | Sign a file |
| `verify(document)` | Verify a signed document |
| `verify_self()` | Verify agent integrity |
| `get_public_key()` | Get public key for sharing |

## MCP Integration

JACS integrates with Model Context Protocol for authenticated tool calls:

```python
from jacs.mcp import JACSMCPServer
from mcp.server.fastmcp import FastMCP

jacs.load("jacs.config.json")
mcp = JACSMCPServer(FastMCP("My Server"))

@mcp.tool()
def my_tool(data: dict) -> dict:
    return {"result": "signed automatically"}
```

## A2A Integration

JACS provides cryptographic provenance for Google's A2A protocol:

```python
from jacs.a2a import JACSA2AIntegration

a2a = JACSA2AIntegration("jacs.config.json")
agent_card = a2a.export_agent_card(agent_data)
wrapped = a2a.wrap_artifact_with_provenance(artifact, "task")
```

## Post-Quantum Cryptography

JACS supports NIST-standardized post-quantum algorithms:

- **ML-DSA (FIPS-204)**: Quantum-resistant signatures
- **ML-KEM (FIPS-203)**: Quantum-resistant key encapsulation

```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [jacs/](./jacs/) | Core Rust library and CLI |
| [jacspy/](./jacspy/) | Python bindings |
| [jacsnpm/](./jacsnpm/) | Node.js bindings |
| [jacsgo/](./jacsgo/) | Go bindings |

## Version

Current version: **0.5.1**

## License

[Apache 2.0 with Common Clause](./LICENSE) - Free for most commercial uses. Contact hello@hai.io for licensing questions.

---
2024, 2025, 2026 https://hai.ai
