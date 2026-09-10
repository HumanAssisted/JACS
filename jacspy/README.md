# JACS Python Library

Cryptographic identity, signing, and verification for AI agents from Python.

> **Registry status (observed 2026-07-11):** PyPI serves `jacs==0.11.3`; this
> branch is source `0.13.0`. Pin the package when exact cross-language contracts
> matter.

```bash
pip install jacs
```

Prebuilt native bindings are distributed via maturin. A normal install does not require compiling Rust.

### First use of the `jacs` command

Installing the Python library does not download a CLI. The first invocation of
the `jacs` command downloads the matching `cli/vX.Y.Z` GitHub Release into an
exact-version and platform-specific user cache. It fetches `sha256sums.txt`
first (with a validated per-asset checksum fallback), verifies SHA-256, rejects
unsafe archive paths, and then executes the cached binary. Linux musl is not a
published CLI target, so musl systems fail clearly instead of downloading the
glibc build. Unsupported platforms or failed verification exit nonzero with the
fallback command `cargo install jacs-cli`. In an active virtual environment the
Python shim may remain first on `PATH`; invoke Cargo's installed binary directly
as `~/.cargo/bin/jacs` (or `.cargo\\bin\\jacs.exe` under your Windows user
profile). If `CARGO_HOME` is set, use its `bin/jacs` executable instead.

Importing or using the Python library performs no CLI download.

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
| `create_agreement_v2()` | Create a standalone Agreement v2 document |
| `sign_agreement_v2()` | Sign as `signer`, `witness`, or `notary` |
| `verify_agreement_v2()` | Verify Agreement v2 hash, policy, transcript, and status |
| `export_agent()` | Export agent JSON for sharing |
| `audit()` | Run a security audit |

## Public human-approved document verification

The wheel build profile enables `human-approval-vendored`: the existing native
WebAuthn verifier with OpenSSL compiled into the extension, without a separate
OpenSSL installation. `maturin develop` uses this same profile. This configures
new builds; it does not claim that an older published wheel has the method.
Release gates check the installed artifact and reject external OpenSSL linkage.
Browser WASM does not provide this verifier.

Rust defaults remain unchanged. A minimal custom extension can omit the feature
using `cargo build -p jacspy --features extension-module,a2a,agreements,attestation`;
it does not expose this method. `human-approval` alone remains available for
custom builds intentionally using a system OpenSSL installation.

```python
from jacs import SimpleAgent

report = SimpleAgent.verify_human_approved_document(
    bundle_json, expected_json, authority_json, provenance_json
)
```

This static method needs no agent, signing key, configuration, or network
lookup. All four arguments are JSON strings. Read stored public evidence into
`bundle_json`; select the expected human/action/credential and the two public
key pins from your application's trusted state, not from the bundle. The
complete report is a dict. Success confirms retained proof and document
integrity, **not** permission to execute now: `current` remains
`not_evaluated`. Live authorization, revocation and one-use checks stay with
the relying application. Feature-enabled tests require
`JACS_TEST_HUMAN_APPROVAL=1 pytest tests/test_human_approved_document.py`.

## Request authentication and signed events

The instance-based `SimpleAgent` exposes the transport protocol helpers. Build
the header from the exact request values that will be sent:

```python
import json
from jacs import SimpleAgent

agent, _ = SimpleAgent.ephemeral(algorithm="ed25519")
body = '{"action":"approve"}'
authorization = agent.build_request_auth_header(
    "POST",
    "https://api.example.com/v1/jobs?mode=strict",
    body,
    "jobs-api",
)
assert authorization.startswith("JACS v2.")

envelope = agent.sign_response(json.dumps({"decision": "allow"}))
signer_id = json.loads(envelope)["jacsSignature"]["agentID"]
server_keys = json.dumps({signer_id: agent.get_public_key_pem()})
verified = json.loads(agent.unwrap_signed_event(envelope, server_keys))
assert verified["verified"] is True
assert verified["data"]["decision"] == "allow"
```

`build_request_auth_header()` accepts `bytes` for arbitrary request bodies or `str`
(encoded as UTF-8), and binds the exact bytes with method, absolute URL
including query, audience, signer/key, issue time, and nonce. Do not serialize
the body again after building the header. `sign_response()` emits a `2.0.0`
envelope whose `jacs-response-v2` signature covers both payload and metadata.
`unwrap_signed_event()` is fail-closed: plain events, legacy payload-only
envelopes, unknown signers, and mutations raise instead of returning data.

Multi-replica consumers should release signed-event payloads through their own
shared atomic replay store:

```python
from jacs import unwrap_signed_event_with_replay_store

# store.scope must be "shared". consume(key, ttl_seconds) returns True only
# for the first atomic consumer and False for a duplicate.
verified = await unwrap_signed_event_with_replay_store(
    agent,
    envelope,
    server_keys,
    store,
)
```

Native verification and freshness checks run before the store is called and
return no payload. The helper validates the exact-input digest, consumes the
native replay key once, rechecks expiry, and only then returns `data` with its
authenticated signer, timestamp, algorithm, and document ID. Store failures,
timeouts, invalid results, process-local stores, duplicates, and expiry all fail
closed with a stable `ReplayError.code`.

The `server_keys` object is a trust decision, not discovery: each key must be
pinned or resolved under the application's configured policy. Successful
verification proves possession of that key; it does not independently prove a
person, organization, domain, or other real-world identity.

The old no-argument `build_auth_header()` remains available for source
compatibility and emits a WARN because it does not bind the request. Migrate
clients and servers together to `JACS v2`; strict deployments can reject the
legacy method with `JACS_REJECT_UNBOUND_AUTH_HEADER=true`.

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

## Agreement v2

Use Agreement v2 for new multi-agent consent workflows:

```python
from jacs import SimpleAgent

agent, info = SimpleAgent.ephemeral(algorithm="ed25519")
agent_id = info["agent_id"]

agreement = agent.create_agreement_v2({
    "title": "Refund approval",
    "description": "Approval for a bounded refund.",
    "terms": "Refund up to $25 for order 123.",
    "status": "proposed",
    "parties": [{"agentId": agent_id, "agentType": "ai", "role": "signer"}],
    "signaturePolicy": {"partyQuorum": "all", "witnessRequired": 0, "notaryRequired": 0},
    "controllers": [agent_id],
})

signed = agent.sign_agreement_v2(agreement, "signer")
assert agent.verify_agreement_v2(signed)["valid"]
```

The same operations are available as module-level functions once an agent is loaded (`quickstart()` / `create()` / `load()`), matching Node's `@hai.ai/jacs/simple` surface:

```python
import jacs.simple as jacs

jacs.quickstart(name="my-agent", domain="agent.example.com")
agent_id = jacs.get_agent_info().agent_id

agreement = jacs.create_agreement_v2({
    "title": "Refund approval",
    "description": "Approval for a bounded refund.",
    "terms": "Refund up to $25 for order 123.",
    "status": "proposed",
    "parties": [{"agentId": agent_id, "agentType": "ai", "role": "signer"}],
    "signaturePolicy": {"partyQuorum": "all", "witnessRequired": 0, "notaryRequired": 0},
    "controllers": [agent_id],
})

signed = jacs.sign_agreement_v2(agreement, "signer")
assert jacs.verify_agreement_v2(signed)["valid"]
```

Verifying another agent's agreement signature requires that agent's public key, so distinct agents must share a `data_directory` or exchange public keys; ephemeral agents verify only their own signatures.

The older `create_agreement()` / `sign_agreement()` / `check_agreement()` methods remain for simple `jacsAgreement` sidecars on existing documents.

## Framework adapters

```bash
pip install jacs[langchain]    # LangChain / LangGraph
pip install jacs[fastapi]      # FastAPI / Starlette
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
