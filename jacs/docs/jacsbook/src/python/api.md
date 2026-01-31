# API Reference

Complete API documentation for the `jacs` Python package.

## Installation

```bash
pip install jacs
```

## Core Module

```python
import jacs
from jacs import JacsAgent
```

---

## JacsAgent Class

The `JacsAgent` class is the primary interface for JACS operations. Each instance maintains its own state and can be used independently, allowing multiple agents in the same process.

### Constructor

```python
JacsAgent()
```

Creates a new empty JacsAgent instance. Call `load()` to initialize with a configuration.

**Example:**
```python
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')
```

---

### agent.load(config_path)

Load and initialize the agent from a configuration file.

**Parameters:**
- `config_path` (str): Path to the JACS configuration file

**Returns:** str - The loaded agent's JSON

**Example:**
```python
agent = jacs.JacsAgent()
agent_json = agent.load('./jacs.config.json')
print('Agent loaded:', json.loads(agent_json)['jacsId'])
```

---

### agent.create_document(document_string, custom_schema=None, output_filename=None, no_save=False, attachments=None, embed=False)

Create and sign a new JACS document.

**Parameters:**
- `document_string` (str): JSON string of the document content
- `custom_schema` (str, optional): Path to a custom JSON Schema for validation
- `output_filename` (str, optional): Filename to save the document
- `no_save` (bool, optional): If True, don't save to storage (default: False)
- `attachments` (str, optional): Path to file attachments
- `embed` (bool, optional): If True, embed attachments in the document

**Returns:** str - The signed document as a JSON string

**Example:**
```python
# Basic document creation
doc = agent.create_document(json.dumps({
    'title': 'My Document',
    'content': 'Hello, World!'
}))

# With custom schema
validated_doc = agent.create_document(
    json.dumps({'title': 'Validated', 'amount': 100}),
    custom_schema='./schemas/invoice.schema.json'
)

# Without saving
temp_doc = agent.create_document(
    json.dumps({'data': 'temporary'}),
    no_save=True
)

# With attachments
doc_with_file = agent.create_document(
    json.dumps({'report': 'Monthly Report'}),
    attachments='./report.pdf',
    embed=True
)
```

---

### agent.verify_document(document_string)

Verify a document's signature and hash integrity.

**Parameters:**
- `document_string` (str): The signed document JSON string

**Returns:** bool - True if the document is valid

**Example:**
```python
is_valid = agent.verify_document(signed_document_json)
if is_valid:
    print('Document signature verified')
else:
    print('Document verification failed')
```

---

### agent.verify_signature(document_string, signature_field=None)

Verify a document's signature with an optional custom signature field.

**Parameters:**
- `document_string` (str): The signed document JSON string
- `signature_field` (str, optional): Name of the signature field (default: 'jacsSignature')

**Returns:** bool - True if the signature is valid

**Example:**
```python
# Verify default signature field
is_valid = agent.verify_signature(doc_json)

# Verify custom signature field
is_valid_custom = agent.verify_signature(doc_json, 'customSignature')
```

---

### agent.update_document(document_key, new_document_string, attachments=None, embed=False)

Update an existing document, creating a new version.

**Parameters:**
- `document_key` (str): The document key in format `"id:version"`
- `new_document_string` (str): The modified document as JSON string
- `attachments` (list, optional): List of attachment file paths
- `embed` (bool, optional): If True, embed attachments

**Returns:** str - The updated document as a JSON string

**Example:**
```python
# Parse existing document to get key
doc = json.loads(signed_doc)
document_key = f"{doc['jacsId']}:{doc['jacsVersion']}"

# Update the document
updated_doc = agent.update_document(
    document_key,
    json.dumps({
        **doc,
        'title': 'Updated Title',
        'content': 'Modified content'
    })
)
```

---

### agent.create_agreement(document_string, agent_ids, question=None, context=None, agreement_field_name=None)

Add an agreement requiring multiple agent signatures to a document.

**Parameters:**
- `document_string` (str): The document JSON string
- `agent_ids` (list): List of agent IDs required to sign
- `question` (str, optional): The agreement question
- `context` (str, optional): Additional context for the agreement
- `agreement_field_name` (str, optional): Field name for the agreement (default: 'jacsAgreement')

**Returns:** str - The document with agreement as a JSON string

**Example:**
```python
doc_with_agreement = agent.create_agreement(
    signed_document_json,
    ['agent-1-uuid', 'agent-2-uuid', 'agent-3-uuid'],
    question='Do you agree to these terms?',
    context='Q1 2024 Service Agreement',
    agreement_field_name='jacsAgreement'
)
```

---

### agent.sign_agreement(document_string, agreement_field_name=None)

Sign an agreement as the current agent.

**Parameters:**
- `document_string` (str): The document with agreement JSON string
- `agreement_field_name` (str, optional): Field name of the agreement (default: 'jacsAgreement')

**Returns:** str - The document with this agent's signature added

**Example:**
```python
signed_agreement = agent.sign_agreement(
    doc_with_agreement_json,
    'jacsAgreement'
)
```

---

### agent.check_agreement(document_string, agreement_field_name=None)

Check the status of an agreement (which agents have signed).

**Parameters:**
- `document_string` (str): The document with agreement JSON string
- `agreement_field_name` (str, optional): Field name of the agreement (default: 'jacsAgreement')

**Returns:** str - JSON string with agreement status

**Example:**
```python
status_json = agent.check_agreement(signed_agreement_json)
status = json.loads(status_json)

print('Required signers:', status['required'])
print('Signatures received:', status['signed'])
print('Complete:', status['complete'])
```

---

### agent.sign_string(data)

Sign arbitrary string data with the agent's private key.

**Parameters:**
- `data` (str): The data to sign

**Returns:** str - Base64-encoded signature

**Example:**
```python
signature = agent.sign_string('Important message')
print('Signature:', signature)
```

---

### agent.verify_string(data, signature_base64, public_key, public_key_enc_type)

Verify a signature on arbitrary string data.

**Parameters:**
- `data` (str): The original data
- `signature_base64` (str): The base64-encoded signature
- `public_key` (bytes): The public key as bytes
- `public_key_enc_type` (str): The key algorithm (e.g., 'ring-Ed25519')

**Returns:** bool - True if the signature is valid

**Example:**
```python
is_valid = agent.verify_string(
    'Important message',
    signature_base64,
    public_key_bytes,
    'ring-Ed25519'
)
```

---

### agent.sign_request(params)

Sign a request payload, wrapping it in a JACS document.

**Parameters:**
- `params` (any): The request payload (will be JSON serialized)

**Returns:** str - JACS-signed request as a JSON string

**Example:**
```python
signed_request = agent.sign_request({
    'method': 'GET',
    'path': '/api/data',
    'timestamp': datetime.now().isoformat(),
    'body': {'query': 'value'}
})
```

---

### agent.verify_response(document_string)

Verify a JACS-signed response and extract the payload.

**Parameters:**
- `document_string` (str): The JACS-signed response

**Returns:** dict - Dictionary containing the verified payload

**Example:**
```python
result = agent.verify_response(jacs_response_string)
payload = result.get('payload')
print('Verified payload:', payload)
```

---

### agent.verify_response_with_agent_id(document_string)

Verify a response and return both the payload and signer's agent ID.

**Parameters:**
- `document_string` (str): The JACS-signed response

**Returns:** dict - Dictionary with payload and agent ID

**Example:**
```python
result = agent.verify_response_with_agent_id(jacs_response_string)
print('Payload:', result['payload'])
print('Signed by agent:', result['agentId'])
```

---

### agent.verify_agent(agent_file=None)

Verify the agent's own signature and hash, or verify another agent file.

**Parameters:**
- `agent_file` (str, optional): Path to an agent file to verify

**Returns:** bool - True if the agent is valid

**Example:**
```python
# Verify the loaded agent
is_valid = agent.verify_agent()

# Verify another agent file
is_other_valid = agent.verify_agent('./other-agent.json')
```

---

### agent.update_agent(new_agent_string)

Update the agent document with new data.

**Parameters:**
- `new_agent_string` (str): The modified agent document as JSON string

**Returns:** str - The updated agent document

**Example:**
```python
current_agent = json.loads(agent.load('./jacs.config.json'))
updated_agent = agent.update_agent(json.dumps({
    **current_agent,
    'description': 'Updated description'
}))
```

---

### agent.sign_agent(agent_string, public_key, public_key_enc_type)

Sign another agent's document with a registration signature.

**Parameters:**
- `agent_string` (str): The agent document to sign
- `public_key` (bytes): The public key as bytes
- `public_key_enc_type` (str): The key algorithm

**Returns:** str - The signed agent document

**Example:**
```python
signed_agent = agent.sign_agent(
    external_agent_json,
    public_key_bytes,
    'ring-Ed25519'
)
```

---

## Module-Level Functions

These functions operate on a global agent singleton and are maintained for backwards compatibility. **New code should use the `JacsAgent` class instead.**

### jacs.load(config_path)

Load the global agent from a configuration file.

```python
import jacs
jacs.load('./jacs.config.json')
```

### jacs.sign_request(data)

Sign a request using the global agent.

```python
signed = jacs.sign_request({'method': 'tools/call', 'params': {...}})
```

### jacs.verify_request(data)

Verify an incoming request using the global agent.

```python
payload = jacs.verify_request(incoming_request_string)
```

### jacs.sign_response(data)

Sign a response using the global agent.

```python
signed = jacs.sign_response({'result': 'success'})
```

### jacs.verify_response(data)

Verify an incoming response using the global agent.

```python
result = jacs.verify_response(response_string)
payload = result.get('payload')
```

---

## MCP Module

```python
from jacs.mcp import JACSMCPServer, JACSMCPClient
```

### JACSMCPServer(mcp_server)

Wraps a FastMCP server with JACS authentication middleware.

**Parameters:**
- `mcp_server`: A FastMCP server instance

**Returns:** The wrapped server with JACS middleware

**Example:**
```python
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP

server = FastMCP("My Server")
authenticated = JACSMCPServer(server)
app = authenticated.sse_app()
```

### JACSMCPClient(url, **kwargs)

Creates a FastMCP client with JACS authentication interceptors.

**Parameters:**
- `url`: The MCP server SSE endpoint URL
- `**kwargs`: Additional arguments passed to the FastMCP Client

**Returns:** A FastMCP Client with JACS interceptors

**Example:**
```python
from jacs.mcp import JACSMCPClient

client = JACSMCPClient("http://localhost:8000/sse")
async with client:
    result = await client.call_tool("my_tool", {"arg": "value"})
```

---

## Configuration

### Configuration File Format

Create a `jacs.config.json` file:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_agent_id_and_version": "your-agent-id:version",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_private_key_filename": "private.pem",
  "jacs_agent_public_key_filename": "public.pem",
  "jacs_data_directory": "./jacs_data",
  "jacs_default_storage": "fs",
  "jacs_key_directory": "./jacs_keys"
}
```

### Configuration Options

| Field | Type | Description |
|-------|------|-------------|
| `jacs_agent_id_and_version` | string | Agent ID and version in format `"id:version"` |
| `jacs_agent_key_algorithm` | string | Signing algorithm: `"ring-Ed25519"`, `"RSA-PSS"`, `"pq-dilithium"`, `"pq2025"` |
| `jacs_agent_private_key_filename` | string | Private key filename |
| `jacs_agent_public_key_filename` | string | Public key filename |
| `jacs_data_directory` | string | Directory for data storage |
| `jacs_key_directory` | string | Directory for key storage |
| `jacs_default_storage` | string | Storage backend: `"fs"`, `"s3"`, `"memory"` |

---

## Error Handling

All methods may raise exceptions. Use try/except for error handling:

```python
try:
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')
    doc = agent.create_document(json.dumps({'data': 'test'}))
except FileNotFoundError as e:
    print(f'Configuration file not found: {e}')
except ValueError as e:
    print(f'Invalid configuration: {e}')
except Exception as e:
    print(f'JACS error: {e}')
```

### Common Exceptions

| Exception | Description |
|-----------|-------------|
| `FileNotFoundError` | Configuration file or key file not found |
| `ValueError` | Invalid configuration or document format |
| `RuntimeError` | Agent not loaded or cryptographic operation failed |

---

## Type Hints

The package supports type hints for better IDE integration:

```python
from jacs import JacsAgent
import json

def process_document(agent: JacsAgent, data: dict) -> str:
    """Create and return a signed document."""
    doc_string = json.dumps(data)
    return agent.create_document(doc_string)

def verify_and_extract(agent: JacsAgent, doc: str) -> dict:
    """Verify document and extract content."""
    if agent.verify_document(doc):
        return json.loads(doc)
    raise ValueError("Document verification failed")
```

---

## Thread Safety

`JacsAgent` instances use internal locking and are thread-safe. You can safely use the same agent instance across multiple threads:

```python
import threading
from jacs import JacsAgent

agent = JacsAgent()
agent.load('./jacs.config.json')

def worker(data):
    # Safe to call from multiple threads
    doc = agent.create_document(json.dumps(data))
    return doc

threads = [
    threading.Thread(target=worker, args=({'id': i},))
    for i in range(10)
]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

---

## See Also

- [Installation](installation.md) - Getting started
- [Basic Usage](basic-usage.md) - Common usage patterns
- [MCP Integration](mcp.md) - Model Context Protocol
- [Examples](../examples/python.md) - More complex examples
