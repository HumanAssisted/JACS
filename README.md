# JACS

**JSON Agent Communication Standard** - Data provenance and cryptographic signing for AI agents.

**[Documentation](https://humanassisted.github.io/JACS/)** | **[Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)** | **[API Reference](https://humanassisted.github.io/JACS/nodejs/api.html)**

## What is JACS?

JACS is an open data provenance toolkit that lets any AI agent or application sign, verify, and track the origin of data. It works standalone -- no server, no account required. Optionally register with [HAI.ai](https://hai.ai) for cross-organization key discovery and attestation.

Available as a library for **Python**, **Node.js**, **Go**, and **Rust**, plus a CLI and MCP servers.

**Why use JACS?**

- **Data provenance**: Know who created data, when, and whether it's been modified
- **Decentralized by default**: Runs entirely local -- keys and signatures stay on your machine
- **Tamper detection**: Cryptographic hashes catch any change, accidental or malicious
- **Non-repudiation**: Signed actions can't be denied
- **Post-quantum ready**: NIST-standardized ML-DSA (FIPS-204) signatures out of the box

## First run (minimal setup)

1. Copy `jacs.config.example.json` to `jacs.config.json` (or use `jacs config create`).
2. Set `JACS_PRIVATE_KEY_PASSWORD` in your environment (never put the password in the config file).
3. Run `jacs agent create` or `jacs init` as documented, then sign/verify as in Quick Start below.

For runtime signing, set `JACS_PRIVATE_KEY_PASSWORD` (or use a keychain). The CLI can prompt during init; scripts and servers must set the env var.

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
| `create(name, options)` | Create a new agent programmatically (non-interactive) |
| `load(config)` | Load agent from config file |
| `sign_message(data)` | Sign any JSON data |
| `sign_file(path, embed)` | Sign a file |
| `verify(document)` | Verify a signed document (JSON string) |
| `verify_by_id(id)` | Verify a document by storage ID (`uuid:version`) |
| `reencrypt_key(old, new)` | Re-encrypt the private key with a new password |
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

## Verification and key resolution

When verifying signatures, JACS looks up signers' public keys in an order controlled by `JACS_KEY_RESOLUTION` (comma-separated: `local`, `dns`, `hai`). Default is `local,hai` (local trust store first, then HAI key service). For air-gapped use, set `JACS_KEY_RESOLUTION=local`.

## Supported algorithms

Signing and verification support: **ring-Ed25519**, **RSA-PSS**, **pq2025** (ML-DSA-87, FIPS-204, recommended). `pq-dilithium` is deprecated -- use `pq2025` instead. Set `jacs_agent_key_algorithm` in config or `JACS_AGENT_KEY_ALGORITHM` in the environment.

## Troubleshooting

- **Config not found**: Copy `jacs.config.example.json` to `jacs.config.json` and set required env vars (see First run).
- **Private key decryption failed**: Wrong password or wrong key file. Ensure `JACS_PRIVATE_KEY_PASSWORD` matches the password used when generating keys.
- **Required environment variable X not set**: Set the variable per the [config docs](https://humanassisted.github.io/JACS/); common ones are `JACS_KEY_DIRECTORY`, `JACS_DATA_DIRECTORY`, `JACS_AGENT_PRIVATE_KEY_FILENAME`, `JACS_AGENT_PUBLIC_KEY_FILENAME`, `JACS_AGENT_KEY_ALGORITHM`, `JACS_AGENT_ID_AND_VERSION`.
- **Algorithm detection failed**: Set the `signingAlgorithm` field in the document, or use `JACS_REQUIRE_EXPLICIT_ALGORITHM=true` to require it.

## Post-Quantum Cryptography

JACS supports NIST-standardized post-quantum algorithms:

- **ML-DSA (FIPS-204)**: Quantum-resistant signatures
- **ML-KEM (FIPS-203)**: Quantum-resistant key encapsulation

```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

## How to use JACS

JACS fits into many workflows:

- **Sign AI outputs** so downstream consumers can verify who generated them
- **Sign files and documents** to prove integrity (contracts, reports, configs)
- **Build MCP servers** where every tool call is signed with agent identity
- **Establish agent-to-agent trust** with agreements and multi-party signatures
- **Track data provenance** through pipelines where data changes hands
- **Air-gapped environments**: JACS works fully offline with local key storage
- **Protect your agent's identity**: Run a public-facing agent with verifiable signatures while keeping the operator's identity off the internet — see [Use cases: Protecting agent identity](USECASES.md#protecting-your-agents-identity-on-the-internet) for a detailed scenario.

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [jacs/](./jacs/) | Core Rust library and CLI |
| [jacspy/](./jacspy/) | Python bindings |
| [jacsnpm/](./jacsnpm/) | Node.js bindings |
| [jacsgo/](./jacsgo/) | Go bindings |
| [jacs-mcp/](./jacs-mcp/) | MCP server for agent state and HAI integration |

## Version

Current version: **0.6.0**

## License

[Apache 2.0 with Common Clause](./LICENSE) - Free for most commercial uses. Contact hello@hai.io for licensing questions.

---
2024, 2025, 2026 https://hai.ai
