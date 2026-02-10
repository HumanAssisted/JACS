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

## Quick Start

Zero-config -- no manual setup needed. One call creates a persistent agent with keys on disk and you're signing.

### Python

```bash
pip install jacs
```

```python
import jacs.simple as jacs

jacs.quickstart()
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

### Node.js

```bash
npm install @hai.ai/jacs
```

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

# Zero-config quickstart
jacs quickstart

# Sign a document
jacs document create -f mydata.json
```

### Advanced: Loading an existing agent

If you already have an agent (e.g., created by a previous `quickstart()` call), load it explicitly:

1. Ensure `jacs.config.json` exists (created automatically by `quickstart()`, or manually via `jacs config create`).
2. Optionally set `JACS_PRIVATE_KEY_PASSWORD` (if not set, the auto-generated password in `./jacs_keys/.jacs_password` is used).

Then load it in code:

```python
import jacs.simple as jacs
jacs.load("./jacs.config.json")
```

```javascript
const jacs = require('@hai.ai/jacs/simple');
jacs.load('./jacs.config.json');
```

```go
import jacs "github.com/HumanAssisted/JACS/jacsgo"
jacs.Load(nil)
```

## Core API (All Languages)

| Function | Description |
|----------|-------------|
| `quickstart(options?)` | Create a persistent agent with keys on disk -- zero config, no manual setup |
| `create(name, options)` | Create a new agent programmatically (non-interactive) |
| `load(config)` | Load agent from config file |
| `sign_message(data)` | Sign any JSON data |
| `sign_file(path, embed)` | Sign a file |
| `verify(document)` | Verify a signed document (JSON string) |
| `verify_standalone(document, options)` | Verify without loading an agent (one-off) |
| `verify_by_id(id)` | Verify a document by storage ID (`uuid:version`) |
| `register_with_hai(options)` | Register the loaded agent with HAI.ai |
| `get_dns_record(domain, ttl?)` | Get DNS TXT record line for the agent |
| `get_well_known_json()` | Get well-known JSON (e.g. for `/.well-known/jacs-pubkey.json`) |
| `reencrypt_key(old, new)` | Re-encrypt the private key with a new password |
| `verify_self()` | Verify agent integrity |
| `get_public_key()` | Get public key for sharing |
| `audit(options)` | Run a read-only security audit (risks, health checks, summary) |
| `generate_verify_link(document, base_url)` | Generate a shareable hai.ai verification URL for a signed document |

## Use Cases

These scenarios show how teams use JACS today. Each links to a [detailed walkthrough](USECASES.md).

**Prove that pipeline outputs are authentic.** A build service signs every JSON artifact it emits -- deployment configs, test reports, compliance summaries. Downstream teams and auditors verify with a single call; tampering or forgery is caught immediately. [Full scenario](USECASES.md#1-verifying-that-json-files-came-from-a-specific-program)

**Run a public agent without exposing the operator.** An AI agent signs every message it sends but only publishes the public key (via DNS or HAI). Recipients verify origin and integrity cryptographically; the operator's identity never touches the internet. [Full scenario](USECASES.md#2-protecting-your-agents-identity-on-the-internet)

**Add cryptographic provenance in any language.** Finance, healthcare, or any regulated environment: sign every output with `sign_message()`, verify with `verify()`. The same three-line pattern works identically in Python, Node.js, and Go. Auditors get cryptographic proof instead of trust-only logs. [Full scenario](USECASES.md#4-a-go-node-or-python-agent-with-strong-data-provenance)

### Other use cases

- **Sign AI outputs** -- Wrap any model response or generated artifact with a signature before it leaves your service. Downstream consumers call `verify()` to confirm which agent produced it and that nothing was altered in transit.
- **Sign files and documents** -- Contracts, reports, configs, or any file on disk: `sign_file(path)` attaches a cryptographic signature. Recipients verify the file's integrity and origin without trusting the transport layer.
- **Build MCP servers with signed tool calls** -- Every tool invocation through your MCP server can carry the agent's signature automatically, giving clients proof of which agent executed the call and what it returned.
- **Establish agent-to-agent trust** -- Two or more agents can sign agreements and verify each other's identities using the trust store. Multi-party signatures let you build workflows where each step is attributable.
- **Agreement verification is strict** -- `check_agreement` fails until all required signers have signed, so partial approvals cannot be mistaken for completion.
- **Track data provenance through pipelines** -- As data moves between services, each stage signs its output. The final consumer can walk the signature chain to verify every transformation back to the original source.
- **Verify without loading an agent** -- Use `verify_standalone()` when you just need to check a signature in a lightweight service or script. No config file, no trust store, no agent setup required.
- **Register with HAI.ai for key discovery** -- Publish your agent's public key to [HAI.ai](https://hai.ai) with `register_with_hai()` so other organizations can discover and verify your agent without exchanging keys out-of-band.
- **Audit your JACS setup** -- Call `audit()` to check config, keys, trust store health, and re-verify recent documents. Returns structured risks and health checks so you can catch misconfigurations before they matter.
- **Share verification links** -- Generate a `https://hai.ai/jacs/verify?s=...` URL with `generate_verify_link()` and embed it in emails, Slack messages, or web pages. Recipients click to verify the document without installing anything.
- **Air-gapped and offline environments** -- Set `JACS_KEY_RESOLUTION=local` and distribute public keys manually. JACS works fully offline with no network calls once keys are in the local trust store.

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

JACS A2A interoperability now includes foreign-agent signature verification using configured key resolution (`local`, `dns`, `hai`) and publishes `/.well-known/agent-card.json` plus `/.well-known/jwks.json` for verifier compatibility. See the [A2A interoperability guide](./jacs/docs/jacsbook/src/integrations/a2a.md) for deployment details.

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

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [jacs/](./jacs/) | Core Rust library and CLI |
| [jacspy/](./jacspy/) | Python bindings |
| [jacsnpm/](./jacsnpm/) | Node.js bindings |
| [jacsgo/](./jacsgo/) | Go bindings |
| [jacs-mcp/](./jacs-mcp/) | MCP server for agent state and HAI integration |

## Version

Current version: **0.8.0**

## License

[Apache 2.0 with Common Clause](./LICENSE) - Free for most commercial uses. Contact hello@hai.io for licensing questions.

---
2024, 2025, 2026 https://hai.ai
