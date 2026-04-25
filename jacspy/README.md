# JACS Python Library

Cryptographic identity, signing, and verification for AI agents — from Python.

```bash
pip install jacs
```

Prebuilt native bindings via maturin. No Rust compilation during install.

[Full documentation](https://humanassisted.github.io/JACS/) | [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Quick start

```python
import jacs.simple as jacs

info = jacs.quickstart(name="my-agent", domain="my-agent.example.com")
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

`quickstart()` creates a persistent agent with keys on disk. If `jacs.config.json` exists, it loads it; otherwise it creates a new agent.

## Core operations

| Operation | Description |
|-----------|-------------|
| `quickstart(name, domain)` | Create a persistent agent with keys — zero config |
| `load()` | Load an existing agent from config |
| `sign_message()` | Sign any JSON-serializable data |
| `sign_file()` | Sign a file with optional embedding |
| `verify()` | Verify any signed document |
| `verify_standalone()` | Verify without loading an agent |
| `export_agent()` | Export agent JSON for sharing |
| `audit()` | Run a security audit |

## What's new in 0.11.0

*Why this matters:* shared markdown that multiple Python agents review and counter-sign, plus signed images for AI-era provenance, are now first-class — the signature is embedded in the artifact, no sidecar JSON required.

```python
import jacs.simple as jacs
from jacs import MissingSignatureError

jacs.load("./jacs.config.json")

# Text — permissive verify (default)
jacs.sign_text("README.md")
result = jacs.verify_text("README.md")
print(result.status)  # 'signed' | 'missing_signature' | 'malformed'

# Hard-fail if the file isn't signed
try:
    jacs.verify_text("README.md", strict=True)
except MissingSignatureError as e:
    print("not signed:", e)

# Override the trust store with a directory of <signer_id>.public.pem files
jacs.verify_text("README.md", key_dir="./trusted-keys/")

# Images
jacs.sign_image("photo.png", out="signed.png")
v = jacs.verify_image("signed.png")
print(v.status)  # 'valid'
v_strict = jacs.verify_image("signed.png", strict=True)  # raises if not signed

# Extract the embedded provenance payload (decoded JSON by default)
payload = jacs.extract_media_signature("signed.png")
```

The same five methods are available on the instance-based `JacsClient` for multi-agent processes.

A JACS inline signature proves "agent X signed these canonical bytes at their claimed time." It does not prove first creation or legal ownership.

## Verify without an agent

```python
result = jacs.verify_standalone(signed_json, key_directory="./keys")
```

Cross-language interop tested on every commit — documents signed in Rust or Node.js verify identically in Python.

## Framework adapters

```bash
pip install jacs[langchain]    # LangChain / LangGraph
pip install jacs[fastapi]      # FastAPI / Starlette
pip install jacs[crewai]       # CrewAI
pip install jacs[anthropic]    # Anthropic / Claude SDK
pip install jacs[a2a]          # A2A protocol
pip install jacs[all]          # Everything
```

## Instance-based API

For multiple agents in one process:

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="example.com")
signed = client.sign_message({"action": "approve"})
```

See [DEVELOPMENT.md](https://github.com/HumanAssisted/JACS/blob/main/DEVELOPMENT.md) for the full API reference, advanced usage (agreements, A2A, attestation, headless loading), framework adapter examples, and testing utilities.

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html)
- [Framework Adapters](https://humanassisted.github.io/JACS/python/adapters.html)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](./examples/)
