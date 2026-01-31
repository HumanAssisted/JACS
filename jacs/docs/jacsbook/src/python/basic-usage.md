# Basic Usage

This chapter covers fundamental JACS operations in Python, including agent initialization, document creation, signing, and verification.

## Initializing an Agent

### Create and Load Agent

```python
import jacs

# Create a new agent instance
agent = jacs.JacsAgent()

# Load configuration from file
agent.load('./jacs.config.json')
```

### Configuration File

Create `jacs.config.json`:

```json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys",
  "jacs_default_storage": "fs",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_agent_id_and_version": "agent-uuid:version-uuid"
}
```

## Creating Documents

### Basic Document Creation

```python
import jacs
import json

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create a document from JSON
document_data = {
    "title": "Project Proposal",
    "content": "Quarterly development plan",
    "budget": 50000
}

signed_document = agent.create_document(json.dumps(document_data))
print('Signed document:', signed_document)
```

### With Custom Schema

Validate against a custom JSON Schema:

```python
signed_document = agent.create_document(
    json.dumps(document_data),
    './schemas/proposal.schema.json'  # custom schema path
)
```

### With Output File

```python
signed_document = agent.create_document(
    json.dumps(document_data),
    None,                     # no custom schema
    './output/proposal.json'  # output filename
)
```

### Without Saving

```python
signed_document = agent.create_document(
    json.dumps(document_data),
    None,   # no custom schema
    None,   # no output filename
    True    # no_save = True
)
```

### With Attachments

```python
signed_document = agent.create_document(
    json.dumps(document_data),
    None,                        # no custom schema
    None,                        # no output filename
    False,                       # save the document
    './attachments/report.pdf',  # attachment path
    True                         # embed files
)
```

## Verifying Documents

### Verify Document Signature

```python
# Verify a document's signature and hash
is_valid = agent.verify_document(signed_document_json)
print('Document valid:', is_valid)
```

### Verify Specific Signature Field

```python
# Verify with a custom signature field
is_valid = agent.verify_signature(
    signed_document_json,
    'jacsSignature'  # signature field name
)
```

## Updating Documents

### Update Existing Document

```python
# Original document key format: "id:version"
document_key = 'doc-uuid:version-uuid'

# Modified document content (must include jacsId and jacsVersion)
updated_data = {
    "jacsId": "doc-uuid",
    "jacsVersion": "version-uuid",
    "title": "Updated Proposal",
    "content": "Revised quarterly plan",
    "budget": 75000
}

updated_document = agent.update_document(
    document_key,
    json.dumps(updated_data)
)

print('Updated document:', updated_document)
```

### Update with New Attachments

```python
updated_document = agent.update_document(
    document_key,
    json.dumps(updated_data),
    ['./new-report.pdf'],  # new attachments
    True                   # embed files
)
```

## Signing and Verification

### Sign Arbitrary Data

```python
# Sign any string data
signature = agent.sign_string('Important message to sign')
print('Signature:', signature)
```

### Verify Arbitrary Data

```python
# Verify a signature on string data
is_valid = agent.verify_string(
    'Important message to sign',  # original data
    signature_base64,             # base64 signature
    public_key_bytes,             # public key as bytes
    'ring-Ed25519'                # algorithm
)
```

## Working with Agreements

### Create an Agreement

```python
# Add agreement requiring multiple agent signatures
document_with_agreement = agent.create_agreement(
    signed_document_json,
    ['agent1-uuid', 'agent2-uuid'],           # required signers
    'Do you agree to these terms?',            # question
    'Q1 2024 service contract',                # context
    'jacsAgreement'                            # field name
)
```

### Sign an Agreement

```python
# Sign the agreement as the current agent
signed_agreement = agent.sign_agreement(
    document_with_agreement_json,
    'jacsAgreement'  # agreement field name
)
```

### Check Agreement Status

```python
# Check which agents have signed
status = agent.check_agreement(
    document_with_agreement_json,
    'jacsAgreement'
)

print('Agreement status:', json.loads(status))
```

## Agent Operations

### Verify Agent

```python
# Verify the loaded agent's signature
is_valid = agent.verify_agent()
print('Agent valid:', is_valid)

# Verify a specific agent file
is_valid_other = agent.verify_agent('./other-agent.json')
```

### Update Agent

```python
# Update agent document
updated_agent_json = agent.update_agent(json.dumps({
    "jacsId": "agent-uuid",
    "jacsVersion": "version-uuid",
    "name": "Updated Agent Name",
    "description": "Updated description"
}))
```

### Sign External Agent

```python
# Sign another agent's document with registration signature
signed_agent_json = agent.sign_agent(
    external_agent_json,
    public_key_bytes,
    'ring-Ed25519'
)
```

## Request/Response Signing

### Sign a Request

```python
# Sign request parameters as a JACS document
signed_request = agent.sign_request({
    "method": "GET",
    "path": "/api/resource",
    "timestamp": datetime.now().isoformat(),
    "body": {"query": "data"}
})
```

### Verify a Response

```python
# Verify a signed response
result = agent.verify_response(signed_response_json)
print('Response valid:', result)

# Verify and get signer's agent ID
result_with_id = agent.verify_response_with_agent_id(signed_response_json)
print('Signer ID:', result_with_id)
```

## Utility Functions

### Hash String

```python
import jacs

# SHA-256 hash of a string
hash_value = jacs.hash_string('data to hash')
print('Hash:', hash_value)
```

### Create Configuration

```python
import jacs

# Programmatically create a config JSON string
config_json = jacs.create_config(
    jacs_data_directory='./jacs_data',
    jacs_key_directory='./jacs_keys',
    jacs_agent_key_algorithm='ring-Ed25519',
    jacs_default_storage='fs'
)

print('Config:', config_json)
```

## Error Handling

```python
import jacs

agent = jacs.JacsAgent()

try:
    agent.load('./jacs.config.json')
except Exception as error:
    print(f'Failed to load agent: {error}')

try:
    doc = agent.create_document(json.dumps({'data': 'test'}))
    print('Document created')
except Exception as error:
    print(f'Failed to create document: {error}')

try:
    is_valid = agent.verify_document(invalid_json)
except Exception as error:
    print(f'Verification failed: {error}')
```

## Complete Example

```python
import jacs
import json

def main():
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Create a task document
    task = {
        "title": "Code Review",
        "description": "Review pull request #123",
        "assignee": "developer-uuid",
        "deadline": "2024-02-01"
    }

    signed_task = agent.create_document(json.dumps(task))
    print('Task created')

    # Verify the task
    if agent.verify_document(signed_task):
        print('Task signature valid')

    # Create agreement for task acceptance
    task_with_agreement = agent.create_agreement(
        signed_task,
        ['manager-uuid', 'developer-uuid'],
        'Do you accept this task assignment?'
    )

    # Sign the agreement
    signed_agreement = agent.sign_agreement(task_with_agreement)
    print('Agreement signed')

    # Check agreement status
    status = agent.check_agreement(signed_agreement)
    print('Status:', status)

    # Hash some data for reference
    task_hash = jacs.hash_string(signed_task)
    print('Task hash:', task_hash)

if __name__ == "__main__":
    main()
```

## Working with Document Data

### Parse Signed Documents

```python
import json

# Create and sign a document
doc_data = {"title": "My Document", "content": "Hello, World!"}
signed_doc = agent.create_document(json.dumps(doc_data))

# Parse the signed document to access JACS fields
parsed = json.loads(signed_doc)
print('Document ID:', parsed.get('jacsId'))
print('Document Version:', parsed.get('jacsVersion'))
print('Signature:', parsed.get('jacsSignature'))
```

### Document Key Format

```python
# Document keys combine ID and version
doc_id = parsed['jacsId']
doc_version = parsed['jacsVersion']
document_key = f"{doc_id}:{doc_version}"

# Use the key for updates
updated_doc = agent.update_document(document_key, json.dumps({
    **parsed,
    "content": "Updated content"
}))
```

## Configuration Management

### Load from File

```python
import jacs

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')
```

### Environment Variables

JACS reads environment variables that override configuration file settings:

```bash
export JACS_DATA_DIRECTORY="./production_data"
export JACS_KEY_DIRECTORY="./production_keys"
export JACS_AGENT_KEY_ALGORITHM="ring-Ed25519"
export JACS_DEFAULT_STORAGE="fs"
```

### Programmatic Configuration

```python
import jacs
import json
import os

# Create config programmatically
config_json = jacs.create_config(
    jacs_data_directory='./jacs_data',
    jacs_key_directory='./jacs_keys',
    jacs_agent_key_algorithm='ring-Ed25519',
    jacs_default_storage='fs'
)

# Write to file
with open('jacs.config.json', 'w') as f:
    f.write(config_json)

# Then load it
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')
```

## Next Steps

- [MCP Integration](mcp.md) - Model Context Protocol support
- [FastMCP Integration](fastmcp.md) - Build advanced MCP servers
- [API Reference](api.md) - Complete API documentation
