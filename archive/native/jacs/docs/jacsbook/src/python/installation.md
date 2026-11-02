# Python Installation

Install the published native package:

```bash
python -m pip install jacs==0.15.0
```

Published 0.15.0 wheels support Python 3.10–3.14 on macOS arm64/x86_64,
Linux arm64/x86_64 glibc, and Linux x86_64 musl. This checkout requires
Python 3.11–3.14. A compatible wheel needs no Rust compiler. See the
[release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
for platform evidence; later source changes are not automatically in the wheel.

## Try signing

```python
from jacs.client import JacsClient

client = JacsClient.ephemeral()
signed = client.sign_message({"message": "Hello from Python"})
assert client.verify(signed.raw).valid
```

For an identity that survives process restarts:

```python
client = JacsClient.quickstart(name="my-agent", domain="my-agent.example.com")
signed = client.sign_message({"message": "Persistent identity"})
assert client.verify(signed.raw).valid
```

New agents default to `pq2025` (ML-DSA-87). Quickstart loads an existing
configuration or creates encrypted keys. Preserve the password through a host
secret source or keychain; an automatically generated password may otherwise
survive only in-process. See
[native password bootstrap](../getting-started/quick-start.md#native-password-bootstrap).

## Optional integrations

```bash
python -m pip install "jacs[mcp]"
python -m pip install "jacs[fastapi]"
python -m pip install "jacs[langchain,langgraph]"
python -m pip install "jacs[anthropic]"
python -m pip install "jacs[a2a-server]"
```

Install only the extras you need. The `a2a` extra adds no dependencies;
`a2a-server` supplies FastAPI and Uvicorn.

## CLI and source builds

The Python `jacs` command downloads and caches the matching CLI release on
first use and verifies its SHA-256. Importing the library downloads nothing.
Unsupported platforms fail; no musl CLI archive is published. Alternatively
install the portable CLI with `cargo install jacs-cli` and start its
verify-only MCP server with `jacs mcp`. If the Python shim shadows Cargo's
binary, invoke the binary in Cargo's `bin` directory explicitly.

Native configuration commands belong to the separate compatibility CLI:
`cargo install jacs-cli-compat` installs `jacs-compat`. Prefer the Python
quickstart above to create a Python agent.

For source builds, follow the
[native development guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md)
from the complete repository. Native bindings use a separate Cargo workspace.

Continue with [Basic Usage](basic-usage.md), [MCP](mcp.md), or
[Framework Adapters](adapters.md).
