# Simplified API

The simplified API (`jacs.simple`) provides a streamlined, module-level interface for common JACS operations. It's designed to get you signing and verifying in under 2 minutes.

## Quick Start

```python
import jacs.simple as jacs

# Load your agent
agent = jacs.load("./jacs.config.json")

# Sign a message
signed = jacs.sign_message({"action": "approve", "amount": 100})
print(f"Document ID: {signed.document_id}")

# Verify it
result = jacs.verify(signed.raw)
print(f"Valid: {result.valid}")
```

## When to Use the Simplified API

| Simplified API | JacsAgent Class |
|----------------|-----------------|
| Quick prototyping | Multiple agents in one process |
| Scripts and CLI tools | Complex multi-document workflows |
| MCP tool implementations | Fine-grained control |
| Single-agent applications | Custom error handling |

---

## API Reference

### load(config_path=None)

Load an agent from a configuration file. This must be called before any other operations.

**Parameters:**
- `config_path` (str, optional): Path to jacs.config.json (default: "./jacs.config.json")

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
- `signed_document` (str): The JSON string of the signed document

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
agent_doc["jacsContacts"] = [{"contactFirstName": "Jane", "contactLastName": "Doe"}]

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

# Create a document (must be saved to disk)
original = jacs.sign_message({"status": "pending", "amount": 100})

# Later, update it
doc = json.loads(original.raw)
doc["content"]["status"] = "approved"

updated = jacs.update_document(original.document_id, doc)
new_doc = json.loads(updated.raw)

print(f"New version: {new_doc['jacsVersion']}")
print(f"Previous: {new_doc['jacsPreviousVersion']}")
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

Return the DNS TXT record line for the loaded agent (for DNS-based discovery). Format: `_v1.agent.jacs.{domain}. TTL IN TXT "v=hai.ai; ..."`.

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

All types are Python dataclasses for convenient access:

### AgentInfo

```python
@dataclass
class AgentInfo:
    agent_id: str       # Agent's UUID
    config_path: str    # Path to loaded config
    public_key_path: Optional[str] = None  # Path to public key file
```

### SignedDocument

```python
@dataclass
class SignedDocument:
    raw: str            # Full JSON document with signature
    document_id: str    # Document's UUID (jacsId)
    agent_id: str       # Signing agent's ID
    timestamp: str      # ISO 8601 timestamp
```

### VerificationResult

```python
@dataclass
class VerificationResult:
    valid: bool                  # True if signature verified
    signer_id: Optional[str]     # Agent who signed
    timestamp: Optional[str]     # When it was signed
    attachments: List[Attachment]  # File attachments
    errors: List[str]            # Error messages if invalid
```

### Attachment

```python
@dataclass
class Attachment:
    filename: str       # Original filename
    mime_type: str      # MIME type
    hash: str           # SHA-256 hash
    embedded: bool      # True if content is embedded
    content: Optional[bytes] = None  # Embedded content (if available)
```

### Exceptions

```python
class JacsError(Exception):
    """Base exception for JACS errors."""
    pass

class AgentNotLoadedError(JacsError):
    """Raised when an operation requires a loaded agent."""
    pass
```

---

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
    doc = json.loads(signed.raw)
    print(f"Payment verified from: {verification.signer_id}")
    print(f"Amount: {doc['content']['amount']} {doc['content']['currency']}")
else:
    print(f"Verification failed: {', '.join(verification.errors)}")

# Sign a file
contract_signed = jacs.sign_file("./contract.pdf", embed=True)
print(f"Contract signed: {contract_signed.document_id}")

# Update agent metadata
agent_doc = json.loads(jacs.export_agent())
agent_doc["jacsAgentType"] = "ai"
if not agent_doc.get("jacsContacts") or len(agent_doc["jacsContacts"]) == 0:
    agent_doc["jacsContacts"] = [{"contactFirstName": "AI", "contactLastName": "Agent"}]
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

# Verification doesn't throw - check result.valid
result = jacs.verify("invalid json")
if not result.valid:
    print(f"Verification errors: {result.errors}")
```

---

## See Also

- [Basic Usage](basic-usage.md) - JacsAgent class usage
- [API Reference](api.md) - Complete JacsAgent API
- [MCP Integration](mcp.md) - Model Context Protocol
