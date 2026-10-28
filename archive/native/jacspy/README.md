# JACS Python Library

Cryptographic identity, signing, and verification for AI agents from Python.

This source version requires Python 3.11–3.14, including optional integrations.
Published 0.15.0 wheels support Python 3.10–3.14; use the source requirement
when building this checkout.

> **Published 0.15.0:** `jacs` remains a supported native Python library.
> Wheel platforms, installed-package checks and provenance are recorded in the
> [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md). Its separate native
> workspace remains buildable through the root Makefile and CI.

```bash
python -m pip install jacs==0.15.0
```

Supported wheels need no Rust toolchain.

### First use of the `jacs` command

The first `jacs` command downloads the matching CLI release, verifies SHA-256,
and caches it by version and platform. Importing or using the library downloads
nothing. No musl CLI archive is published; unsupported platforms or verification
failures exit nonzero. The fallback is `cargo install jacs-cli`.

If the Python shim shadows Cargo's binary, invoke `~/.cargo/bin/jacs` directly
(or `%USERPROFILE%\.cargo\bin\jacs.exe` on Windows). With `CARGO_HOME` set, use
its `bin` directory instead.

[Full documentation](https://humanassisted.github.io/JACS/) | [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Quick start

```python
import jacs.simple as jacs

info = jacs.quickstart(name="my-agent", domain="my-agent.example.com")
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

`quickstart()` creates a persistent agent with encrypted keys on disk. If
`jacs.config.json` exists, it loads it. Preserve the password through your host
secret source or keychain for later processes; an automatically generated
password is otherwise retained only in-process. See the
[password guide](https://humanassisted.github.io/JACS/native/getting-started/quick-start.html#native-password-bootstrap).

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
| `verify_agreement_v2()` | Inspect Agreement v2 hashes, signatures and claimed status |
| `export_agent()` | Export agent JSON for sharing |
| `audit()` | Run a security audit |

## Public human-approved document verification

The wheel build profile enables `human-approval-vendored`: the existing native
WebAuthn verifier with OpenSSL compiled into the extension, without a separate
OpenSSL installation. `maturin develop` uses this same profile. This configures
new builds; it does not claim that an older published wheel has the method.
Release gates check the installed artifact and reject external OpenSSL linkage.
Browser WASM does not provide this verifier.

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
the relying application.

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

For multi-replica consumers,
`await unwrap_signed_event_with_replay_store(agent, envelope, server_keys, store)`
requires an application-owned shared atomic replay store implementing the
[Python store protocol](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/python/jacs/replay.py). It fails closed on
duplicates, expiry or store failure. See [replay-store deployment](https://humanassisted.github.io/JACS/native/advanced/security.html#replay-store-deployment)
and the [signed-event contract](https://humanassisted.github.io/JACS/native/advanced/security.html#signed-response-and-event-contract)
before releasing verified payloads.

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
jacs.sign_image("photo.png", "signed.png")
image = jacs.verify_image("signed.png")
print(image.status)  # 'valid'

payload = jacs.extract_media_signature("signed.png")
```

The same methods are available on the instance-based `JacsClient` for multi-agent processes. These signatures prove that an agent signed specific canonical bytes at its claimed time; they do not prove first creation or legal ownership.

## Verify without an agent

```python
result = jacs.verify_standalone(signed_json, key_directory="./keys")
```

JACS uses a shared signed-document format across bindings. See the
[release evidence](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
for installed-consumer checks and their limits.

## Agreement v2

Use Agreement v2 to inspect native compatibility agreement documents:

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
report = agent.verify_agreement_v2(signed)
assert report["mathematicalChecksValid"]
assert report["status"] == "final"
assert report["policyAccepted"] is False
```

Agreement v2 inspection checks signatures and claimed status; `valid` and
`policyAccepted` remain false because this is not application consent-policy
acceptance. Do not authorize an action from these mathematical checks alone.

The same methods are available on `jacs.simple` after `quickstart()` or `load()`.

Verifying another agent's agreement signature requires that agent's public key, so distinct agents must share a `data_directory` or exchange public keys; ephemeral agents verify only their own signatures.

The older `create_agreement()` / `sign_agreement()` / `check_agreement()` methods remain for simple `jacsAgreement` sidecars on existing documents.

## Framework adapters

```bash
pip install "jacs[langchain,langgraph]"  # LangChain / LangGraph
pip install jacs[fastapi]      # FastAPI / Starlette
pip install jacs[anthropic]    # Anthropic / Claude SDK
pip install jacs[a2a]          # A2A protocol
pip install jacs[all]          # Everything
```

Current-source [A2A routes](https://humanassisted.github.io/JACS/native/guides/a2a-serve.html)
serve five direct-root discovery documents, or six for explicit ES256.
Verify the card/JWKS and any root-signed compatibility binding under your trust
policy; discovery and cache freshness do not establish authority. The guide
covers renewal and expiry. New source behavior is not publication evidence.

## Instance-based API

For multiple agents in one process:

```python
from jacs.client import JacsClient

client = JacsClient.quickstart(name="my-agent", domain="example.com")
signed = client.sign_message({"action": "approve"})
```

See the [API reference](https://humanassisted.github.io/JACS/native/python/api.html),
[framework adapters](https://humanassisted.github.io/JACS/native/python/adapters.html),
and [native development guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/DEVELOPMENT.md).

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Verification Guide](https://humanassisted.github.io/JACS/getting-started/verification.html)
- [Framework Adapters](https://humanassisted.github.io/JACS/python/adapters.html)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/examples)
