# JACS Python Library

Cryptographic identity, signing, and verification for AI agents from Python.

```bash
pip install jacs
```

Prebuilt native bindings are distributed via maturin. A normal install does not require compiling Rust.

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
| `quickstart(name, domain)` | Create or load a persistent agent |
| `load()` | Load an existing agent from config |
| `sign_message()` | Sign JSON-serializable data |
| `sign_file()` | Sign a file with optional embedding |
| `verify()` | Verify a signed document |
| `verify_standalone()` | Verify without loading an agent |
| `export_agent()` | Export agent JSON for sharing |
| `audit()` | Run a security audit |

## Text and image provenance

Python exposes the same inline text and image signing surface as the CLI:

```python
import jacs.simple as jacs
from jacs import MissingSignatureError

jacs.load("./jacs.config.json")

# Markdown/text: append and verify an inline signature block.
jacs.sign_text("README.md")
text = jacs.verify_text("README.md")
print(text.status)  # 'signed' | 'missing_signature' | 'malformed'

try:
    jacs.verify_text("README.md", strict=True)
except MissingSignatureError:
    print("not signed")

jacs.verify_text("README.md", key_dir="./trusted-keys/")

# Images: embed and verify a signature in PNG, JPEG, or WebP metadata.
jacs.sign_image("photo.png", out="signed.png")
image = jacs.verify_image("signed.png")
print(image.status)  # 'valid'

payload = jacs.extract_media_signature("signed.png")
```

The same methods are available on the instance-based `JacsClient` for multi-agent processes. These signatures prove that an agent signed specific canonical bytes at its claimed time; they do not prove first creation or legal ownership.

## Verify without an agent

```python
result = jacs.verify_standalone(signed_json, key_directory="./keys")
```

Cross-language interop is tested on every commit. Documents signed in Rust or Node.js verify in Python, and Python-signed documents verify in the other bindings.

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

See [DEVELOPMENT.md](https://github.com/HumanAssisted/JACS/blob/main/DEVELOPMENT.md) for the full API reference, advanced usage, framework adapter examples, and testing utilities.

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html)
- [Framework Adapters](https://humanassisted.github.io/JACS/python/adapters.html)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](./examples/)
