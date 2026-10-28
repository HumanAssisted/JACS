# Simplified API

`jacs.simple` provides one process-wide session for signing and verification.

## Quick Start

Create or load a persistent agent:

```python
import jacs.simple as jacs

info = jacs.quickstart(name="my-agent", domain="my-agent.example.com")
print(info.config_path, info.public_key_path, info.private_key_path)
signed = jacs.sign_message({"action": "approve", "amount": 100})
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}, Signer: {result.signer_id}")
```

{{#include ../_snippets/quickstart-persistent-agent.md}}
Pass `algorithm="ed25519"` to override the default (`pq2025`).

To load an existing agent explicitly, use `load()` instead:

```python
agent = jacs.load("./jacs.config.json")
signed = jacs.sign_message({"action": "approve", "amount": 100})
```

## When to Use the Simplified API

Use `jacs.simple` for one agent per process, `JacsClient` for independent agents,
and lower-level `JacsAgent` when you need direct document/config control.

## API Reference

### quickstart(name, domain, description=None, algorithm=None, config_path=None)

Create or load a persistent agent. See the Quick Start above for password
handling; call this before signing or verifying.

**Parameters:**
- `name` (str, required): Agent name used for first-time creation.
- `domain` (str, required): Agent domain used for DNS/public-key verification workflows.
- `description` (str, optional): Human-readable description.
- `algorithm` (str, optional): Signing algorithm. Default: `"pq2025"`. User-facing choices: `"ed25519"`, `"pq2025"`; `"ring-Ed25519"` is accepted as a legacy alias.
- `config_path` (str, optional): Config path (default: `"./jacs.config.json"`).

**Returns:** `AgentInfo` dataclass

```python
info = jacs.quickstart(name="my-agent", domain="my-agent.example.com")
print(f"Agent ID: {info.agent_id}")
print(f"Config path: {info.config_path}")
print(f"Public key: {info.public_key_path}")
print(f"Private key: {info.private_key_path}")

# Or with a specific algorithm
info = jacs.quickstart(
    name="my-agent",
    domain="my-agent.example.com",
    algorithm="ed25519",
)
```

---

### load(config_path=None, strict=None)

Load a persistent agent from a configuration file. Use this instead of `quickstart(name=..., domain=..., ...)` when you want to load a specific config file explicitly.

**Parameters:**
- `config_path` (str, optional): Path to jacs.config.json (default: "./jacs.config.json")
- `strict` (bool, optional): If True, verification failures raise; if None, uses `JACS_STRICT_MODE` env var

**Returns:** `AgentInfo` dataclass

**Raises:** `JacsError` if config not found or invalid

```python
info = jacs.load("./jacs.config.json")
print(f"Agent ID: {info.agent_id}")
print(f"Config: {info.config_path}")
```

---

### is_loaded()

Check if an agent is currently loaded.

**Returns:** bool

```python
if not jacs.is_loaded():
    jacs.load("./jacs.config.json")
```

---

### get_agent_info()

Get information about the currently loaded agent.

**Returns:** `AgentInfo` or None if no agent is loaded

```python
info = jacs.get_agent_info()
if info:
    print(f"Agent: {info.agent_id}")
```

---

### verify_self()

Verify the loaded agent's own integrity (signature and hash).

**Returns:** `VerificationResult`

**Raises:** `AgentNotLoadedError` if no agent is loaded

```python
result = jacs.verify_self()
if result.valid:
    print("Agent integrity verified")
else:
    print(f"Errors: {result.errors}")
```

---

### sign_message(data)

Sign arbitrary data as a JACS document.

**Parameters:**
- `data` (any): Dict, list, string, or any JSON-serializable value

**Returns:** `SignedDocument`

**Raises:** `AgentNotLoadedError` if no agent is loaded

```python
# Sign a dict
signed = jacs.sign_message({
    "action": "transfer",
    "amount": 500,
    "recipient": "agent-123"
})

print(f"Document ID: {signed.document_id}")
print(f"Signed by: {signed.agent_id}")
print(f"Timestamp: {signed.timestamp}")
print(f"Raw JSON: {signed.raw}")
```

---

### sign_file(file_path, embed=False)

Sign a file with optional content embedding.

**Parameters:**
- `file_path` (str): Path to the file to sign
- `embed` (bool, optional): If True, embed file content in the document (default: False)

**Returns:** `SignedDocument`

**Raises:** `JacsError` if file not found or no agent loaded

```python
# Reference only (stores hash)
signed = jacs.sign_file("contract.pdf", embed=False)

# Embed content (creates portable document)
embedded = jacs.sign_file("contract.pdf", embed=True)
```

---

### verify(signed_document)

Verify a signed document and extract its content.

**Parameters:**
- `signed_document` (str|dict|SignedDocument): The signed document as JSON string, dict, or SignedDocument

**Returns:** `VerificationResult`

**Raises:** `AgentNotLoadedError` if no agent is loaded

```python
result = jacs.verify(signed_json)

if result.valid:
    print(f"Signed by: {result.signer_id}")
    print(f"Timestamp: {result.timestamp}")
else:
    print(f"Invalid: {', '.join(result.errors)}")
```

---

### verify_standalone(document, key_resolution="local", data_directory=None, key_directory=None)

Verify a signed document **without** loading an agent. Use when you only need to verify (e.g. a lightweight API).

**Parameters:** `document` (str|dict), `key_resolution` (str), `data_directory` (str, optional), `key_directory` (str, optional)

**Returns:** `VerificationResult`

---

### HTTP protocol helpers (`SimpleAgent` instances)

The module-level API focuses on durable documents. Request-bound HTTP auth and
signed event helpers live on the instance-based native `SimpleAgent`:

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

envelope = agent.sign_response(json.dumps({"decision": "allow"}))
signer_id = json.loads(envelope)["jacsSignature"]["agentID"]
keys = json.dumps({signer_id: agent.get_public_key_pem()})
verified = json.loads(agent.unwrap_signed_event(envelope, keys))
assert authorization.startswith("JACS v2.")
assert verified["verified"] is True
assert verified["data"]["decision"] == "allow"
```

- `build_request_auth_header(method, url, body="", audience="hai.ai")` binds the
  normalized method, absolute URL including query, exact UTF-8 body bytes,
  audience, signer/key, issue time, and nonce. Serialize the final request body
  before calling it and transmit that string unchanged.
- `sign_response(payload_json)` returns a `2.0.0` envelope whose
  `jacs-response-v2` signature covers payload and all metadata.
- `unwrap_signed_event(event_json, server_keys_json)` returns JSON containing
  verified `data`, `signerId`, `timestamp`, `algorithm`, and `documentId`.
  Plain/unsigned input, legacy payload-only envelopes, unknown signers, and any
  mutation raise; it never successfully returns `verified: false`.

`server_keys_json` is a map from signer ID to a pinned base64 key or PEM string.
It represents the application's configured trust decision. Cryptographic
success proves possession of that key, not a real-world identity by itself.

Legacy no-argument `build_auth_header()` remains available for compatibility
and emits a WARN. Migrate both peers to v2; strict deployments can reject the
legacy method with `JACS_REJECT_UNBOUND_AUTH_HEADER=true`. See
[Security](../advanced/security.md#request-bound-http-authorization).

---

### sign_text(path)

Append a YAML-bodied JACS signature block to the end of a markdown or text file. The file content (everything before the first signature block) is preserved byte-for-byte; multi-signer files are unordered.

**Parameters:** `path` (str): file to sign in place

**Returns:** `SignTextResult`

**Raises:** `RuntimeError` if the file contains a column-zero `-----BEGIN JACS SIGNATURE-----` outside a valid block — see the [inline-text-signing guide](../guides/inline-text-signing.md) for documented workarounds.

```python
jacs.sign_text("README.md")
```

---

### verify_text(path, *, strict=False, key_dir=None)

Verify all signature blocks in a text file. Permissive by default — missing signatures are a typed status, not an error.

**Parameters:**
- `path` (str)
- `strict` (bool, keyword-only): when `True`, raises `MissingSignatureError` if the file is unsigned. Default `False`.
- `key_dir` (str, keyword-only): directory of `<signer_id>.public.pem` files used in addition to the local trust store.

**Returns:** `VerifyTextResult` — `.status` is `'signed' | 'missing_signature' | 'malformed'`; `.signatures` lists per-signer outcomes.

```python
result = jacs.verify_text("README.md")
print(result.status)  # 'signed'

# Strict — missing signature raises
try:
    jacs.verify_text("UNSIGNED.md", strict=True)
except MissingSignatureError:
    print("not signed")
```

See the [inline text signing guide](../guides/inline-text-signing.md) for the full feature set.

---

### sign_image(input_path, output_path, *, robust=False, refuse_overwrite=False)

Embed a JACS signature inside a PNG, JPEG, or WebP image. The signature lives in a metadata chunk (PNG iTXt / JPEG APP11 / WebP XMP).

**Parameters:**
- `input_path` (str): input image
- `output_path` (str): required output path.
- `robust` (bool, keyword-only): opt-in LSB embedding fallback for PNG/JPEG (off by default; WebP deferred).
- `refuse_overwrite` (bool, keyword-only): raise an error if the input already carries a signature.

**Returns:** `SignImageResult`

```python
jacs.sign_image("photo.png", "signed.png")
```

---

### verify_image(path, *, strict=False, key_dir=None)

Verify the embedded signature on an image. Same permissive / strict model as `verify_text`.

**Parameters:** as for `verify_text`.

**Returns:** `VerifyImageResult` with `.status`, optional `.signer_id` and
`.format`. Status values include `valid`, `invalid_signature`, `hash_mismatch`,
`missing_signature`, `key_not_found`, `unsupported_format` and `malformed`.

```python
v = jacs.verify_image("signed.png")
print(v.status)  # 'valid'
```

See the [media signing guide](../guides/media-signing.md) for the full feature set.

---

### extract_media_signature(path, *, raw_payload=False)

Extract the embedded signature payload **without verifying** it.

**Parameters:**
- `path` (str)
- `raw_payload` (bool, keyword-only): emit the base64url wire form instead of decoded JSON. Default `False`.

**Returns:** `Optional[str]`: a JSON string, or the base64url wire form when
`raw_payload=True`; `None` if no signature is present.

```python
import json

payload = jacs.extract_media_signature("signed.png")
if payload is not None:
    print(json.loads(payload))  # Extraction alone does not verify the payload.
```

---

### verify_by_id(document_id)

Verify a document by its storage ID (`uuid:version`) without passing the full JSON. Requires the document to be stored locally (e.g. in the agent's data directory).

**Parameters:** `document_id` (str): Document ID in format `"uuid:version"`

**Returns:** `VerificationResult`

---

### reencrypt_key(old_password, new_password)

Re-encrypt the loaded agent's private key with a new password.

**Parameters:** `old_password` (str), `new_password` (str)

**Raises:** `AgentNotLoadedError` if no agent loaded; `JacsError` if password is wrong

---

### audit(config_path=None, recent_n=None)

Run a read-only security audit and health checks. Returns a dict with `risks`, `health_checks`, `summary`, and `overall_status`. Does not require a loaded agent; does not modify state.

See [Security Model — Security Audit](../advanced/security.md#security-audit-audit) for full details and options.

```python
result = jacs.audit()
print(f"Risks: {len(result['risks'])}, Status: {result['overall_status']}")
```

---

### update_agent(new_agent_data)

Update the agent document with new data and re-sign it.

This function expects a **complete agent document** (not partial updates). Use `export_agent()` to get the current document, modify it, then pass it here.

**Parameters:**
- `new_agent_data` (dict|str): Complete agent document as JSON string or dict

**Returns:** str - The updated and re-signed agent document

**Raises:** `AgentNotLoadedError` if no agent loaded, `JacsError` if validation fails

```python
import json

# Get current agent document
agent_doc = json.loads(jacs.export_agent())

# Modify fields
agent_doc["jacsAgentType"] = "hybrid"
agent_doc["description"] = "Hybrid signing agent"

# Update (creates new version, re-signs, re-hashes)
updated = jacs.update_agent(agent_doc)
new_doc = json.loads(updated)

print(f"New version: {new_doc['jacsVersion']}")
print(f"Previous: {new_doc['jacsPreviousVersion']}")
```

**Valid `jacsAgentType` values:** `"human"`, `"human-org"`, `"hybrid"`, `"ai"`

---

### update_document(document_id, new_document_data, attachments=None, embed=False)

Update an existing document with new data and re-sign it.

**Note:** The original document must have been saved to disk (created without `no_save=True`).

**Parameters:**
- `document_id` (str): The document ID (jacsId) to update
- `new_document_data` (dict|str): Updated document as JSON string or dict
- `attachments` (list, optional): List of file paths to attach
- `embed` (bool, optional): If True, embed attachment contents

**Returns:** `SignedDocument` with the updated document

**Raises:** `JacsError` if document not found, no agent loaded, or validation fails

```python
import json
import jacs as native

# Use a native stored document and its full id:version lookup key.
agent = native.JacsAgent()
agent.load("./jacs.config.json")
original = json.loads(agent.create_document(json.dumps({"content": {"status": "pending"}})))
document_key = f"{original['jacsId']}:{original['jacsVersion']}"
original["content"]["status"] = "approved"
updated = json.loads(agent.update_document(document_key, json.dumps(original), None, None))
print(f"New version: {updated['jacsVersion']}")
print(f"Previous: {updated['jacsPreviousVersion']}")
```

---

### export_agent()

Export the current agent document for sharing or inspection.

**Returns:** str - The agent JSON document

**Raises:** `AgentNotLoadedError` if no agent loaded

```python
agent_doc = jacs.export_agent()
print(agent_doc)

# Parse to inspect
agent = json.loads(agent_doc)
print(f"Agent type: {agent['jacsAgentType']}")
```

---

### get_dns_record(domain, ttl=3600)

Return the DNS TXT record line for the loaded agent (for DNS-based discovery). Format: `_v1.agent.jacs.{domain}. TTL IN TXT "v=jacs; ..."`.

**Returns:** str

---

### get_well_known_json()

Return the well-known JSON object for the loaded agent (e.g. for `/.well-known/jacs-pubkey.json`). Keys: `publicKey`, `publicKeyHash`, `algorithm`, `agentId`.

**Returns:** dict

---

### get_public_key()

Get the loaded agent's public key in PEM format for sharing with others.

**Returns:** str - PEM-encoded public key

**Raises:** `AgentNotLoadedError` if no agent loaded

```python
pem = jacs.get_public_key()
print(pem)
# -----BEGIN PUBLIC KEY-----
# ...
# -----END PUBLIC KEY-----
```

---

## Type Definitions

These result types provide attributes for common operations:

| Type | Key attributes |
| --- | --- |
| `AgentInfo` | `agent_id`, `version`, `config_path`, `public_key_path` |
| `SignedDocument` | `document_id`, `version`, `signer_id`, `payload`, `raw_json`; `raw` aliases `raw_json` |
| `VerificationResult` | `valid`, `signer_id`, `timestamp`, `errors`, `attachments` |
| `Attachment` | `filename`, `mime_type`, `content_hash`, optional `content`, `size_bytes` |

See the [type definitions](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacspy/python/jacs/types.py)
for constructors, defaults and aliases, and [error handling](#error-handling)
for exceptions. Signer timestamps are claims, not an independent time authority.

## Complete Example

```python
import json
import jacs.simple as jacs
from jacs.types import JacsError, AgentNotLoadedError

# Load agent
agent = jacs.load("./jacs.config.json")
print(f"Loaded agent: {agent.agent_id}")

# Verify agent integrity
self_check = jacs.verify_self()
if not self_check.valid:
    raise RuntimeError("Agent integrity check failed")

# Sign a transaction
transaction = {
    "type": "payment",
    "from": agent.agent_id,
    "to": "recipient-agent-uuid",
    "amount": 250.00,
    "currency": "USD",
    "memo": "Q1 Service Payment"
}

signed = jacs.sign_message(transaction)
print(f"Transaction signed: {signed.document_id}")

# Verify the transaction (simulating recipient)
verification = jacs.verify(signed.raw)

if verification.valid:
    print(f"Payment verified from: {verification.signer_id}")
    print(json.loads(signed.raw))  # Inspect the document only after verification.
else:
    print(f"Verification failed: {', '.join(verification.errors)}")

# Sign a file
contract_signed = jacs.sign_file("./contract.pdf", embed=True)
print(f"Contract signed: {contract_signed.document_id}")

# Update agent metadata
agent_doc = json.loads(jacs.export_agent())
agent_doc["jacsAgentType"] = "ai"
agent_doc["description"] = "AI signing agent"
updated_agent = jacs.update_agent(agent_doc)
print("Agent metadata updated")

# Share public key
public_key = jacs.get_public_key()
print("Share this public key for verification:")
print(public_key)
```

---

## MCP Integration

The simplified API works well with FastMCP tool implementations:

```python
from fastmcp import FastMCP
import jacs.simple as jacs

mcp = FastMCP("My Server")

# Load agent once at startup
jacs.load("./jacs.config.json")

@mcp.tool()
def approve_request(request_id: str) -> dict:
    """Approve a request with cryptographic signature."""
    signed = jacs.sign_message({
        "action": "approve",
        "request_id": request_id,
        "approved_by": jacs.get_agent_info().agent_id
    })
    return {"signed_approval": signed.raw}

@mcp.tool()
def verify_approval(signed_json: str) -> dict:
    """Verify a signed approval."""
    result = jacs.verify(signed_json)
    return {
        "valid": result.valid,
        "signer": result.signer_id,
        "errors": result.errors
    }
```

---

## Error Handling

```python
import jacs.simple as jacs
from jacs.types import JacsError, AgentNotLoadedError

try:
    jacs.load("./missing-config.json")
except JacsError as e:
    print(f"Config not found: {e}")

try:
    # Will fail if no agent loaded
    jacs.sign_message({"data": "test"})
except AgentNotLoadedError as e:
    print(f"No agent: {e}")

try:
    jacs.sign_file("/nonexistent/file.pdf")
except JacsError as e:
    print(f"File not found: {e}")

# With an agent loaded and strict mode disabled, inspect result.valid.
# An unloaded agent raises AgentNotLoadedError; strict mode raises VerificationError.
result = jacs.verify("invalid json")
if not result.valid:
    print(f"Verification errors: {result.errors}")
```

---

## See Also

- [Basic Usage](basic-usage.md) - JacsAgent class usage
- [API Reference](api.md) - Complete JacsAgent API
- [MCP Integration](mcp.md) - Model Context Protocol
