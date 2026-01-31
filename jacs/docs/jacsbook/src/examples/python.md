# Python Examples

This chapter provides practical Python examples using the `jacs` (jacspy) package.

## Setup

```bash
# Install dependencies
pip install jacs fastmcp fastapi uvicorn
```

```python
# Initialize JACS
import jacs

agent = jacs.JacsAgent()
agent.load('./jacs.config.json')
```

## Basic Document Operations

### Creating and Signing Documents

```python
import jacs
import json

def create_signed_document():
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Create document content
    content = {
        "title": "Invoice",
        "invoiceNumber": "INV-001",
        "amount": 1500.00,
        "customer": "Acme Corp",
        "items": [
            {"description": "Consulting", "quantity": 10, "price": 150}
        ]
    }

    # Create and sign the document
    signed_doc = agent.create_document(json.dumps(content))

    # Parse the result
    doc = json.loads(signed_doc)
    print(f"Document ID: {doc['jacsId']}")
    print(f"Version: {doc['jacsVersion']}")
    print(f"Signature: {'Present' if 'jacsSignature' in doc else 'Missing'}")

    return doc

if __name__ == "__main__":
    create_signed_document()
```

### Verifying Documents

```python
import jacs
import json

def verify_document(file_path: str) -> bool:
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Read the document
    with open(file_path, 'r') as f:
        doc_string = f.read()

    # Verify signature
    is_valid = agent.verify_document(doc_string)

    if is_valid:
        doc = json.loads(doc_string)
        print("✓ Document signature is valid")
        print(f"  Signed by: {doc.get('jacsSignature', {}).get('agentID')}")
        print(f"  Signed at: {doc.get('jacsSignature', {}).get('date')}")
    else:
        print("✗ Document signature is INVALID")

    return is_valid

if __name__ == "__main__":
    verify_document('./invoice.json')
```

### Updating Documents

```python
import jacs
import json

def update_document(original_path: str, new_content: dict) -> dict:
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Read original document
    with open(original_path, 'r') as f:
        original_doc = f.read()

    # Update with new content (preserves version chain)
    updated_doc = agent.update_document(
        original_doc,
        json.dumps(new_content)
    )

    doc = json.loads(updated_doc)
    print(f"Updated Document ID: {doc['jacsId']}")
    print(f"New Version: {doc['jacsVersion']}")

    return doc

if __name__ == "__main__":
    updated = update_document('./invoice-v1.json', {
        "title": "Invoice",
        "invoiceNumber": "INV-001",
        "amount": 1500.00,
        "customer": "Acme Corp",
        "status": "paid"  # New field
    })
```

## HTTP Server with FastAPI

### Complete FastAPI Server

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse
import jacs
import json

app = FastAPI(title="JACS API")

# Initialize JACS agent at startup
agent = None

@app.on_event("startup")
async def startup():
    global agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

# Health check (no JACS)
@app.get("/health")
async def health():
    return {"status": "ok"}

# JACS-protected endpoint
@app.post("/api/echo")
async def echo(request: Request):
    # Read raw body
    body = await request.body()
    body_str = body.decode('utf-8')

    # Verify JACS request
    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid JACS request")

    # Process and respond
    result = {
        "echo": payload,
        "serverTime": str(datetime.now())
    }

    # Sign response
    signed_response = jacs.sign_response(result)
    return PlainTextResponse(content=signed_response)

# Create document endpoint
@app.post("/api/documents")
async def create_document(request: Request):
    body = await request.body()
    body_str = body.decode('utf-8')

    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid JACS request")

    # Create signed document
    signed_doc = agent.create_document(json.dumps(payload))
    doc = json.loads(signed_doc)

    result = {
        "success": True,
        "documentId": doc['jacsId'],
        "version": doc['jacsVersion']
    }

    signed_response = jacs.sign_response(result)
    return PlainTextResponse(content=signed_response)

# Calculate endpoint
@app.post("/api/calculate")
async def calculate(request: Request):
    body = await request.body()
    body_str = body.decode('utf-8')

    try:
        verified = jacs.verify_request(body_str)
        payload = json.loads(verified).get('payload')
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid JACS request")

    operation = payload.get('operation')
    a = payload.get('a', 0)
    b = payload.get('b', 0)

    if operation == 'add':
        result = a + b
    elif operation == 'subtract':
        result = a - b
    elif operation == 'multiply':
        result = a * b
    elif operation == 'divide':
        result = a / b if b != 0 else None
    else:
        raise HTTPException(status_code=400, detail="Unknown operation")

    response = {"operation": operation, "a": a, "b": b, "result": result}
    signed_response = jacs.sign_response(response)
    return PlainTextResponse(content=signed_response)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
```

### HTTP Client

```python
import jacs
import requests
import json

def call_jacs_api(url: str, payload: dict) -> dict:
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.client.config.json')

    # Sign the request
    signed_request = jacs.sign_request(payload)

    # Send HTTP request
    response = requests.post(
        url,
        data=signed_request,
        headers={"Content-Type": "text/plain"}
    )

    if response.status_code != 200:
        raise Exception(f"HTTP {response.status_code}")

    # Verify and extract response
    verified = jacs.verify_response(response.text)
    return json.loads(verified).get('payload')

if __name__ == "__main__":
    # Call echo endpoint
    echo_result = call_jacs_api(
        'http://localhost:8000/api/echo',
        {"message": "Hello, server!"}
    )
    print("Echo:", echo_result)

    # Call calculate endpoint
    calc_result = call_jacs_api(
        'http://localhost:8000/api/calculate',
        {"operation": "multiply", "a": 7, "b": 6}
    )
    print("Calculate:", calc_result)
```

## MCP Integration

### FastMCP Server with JACS

```python
import jacs
from jacs.mcp import JACSMCPServer
from fastmcp import FastMCP
import uvicorn

# Initialize JACS
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create FastMCP server with JACS
mcp = JACSMCPServer(FastMCP("JACS Demo Server"))

@mcp.tool()
def echo(message: str) -> str:
    """Echo the input message"""
    return f"Echo: {message}"

@mcp.tool()
def calculate(operation: str, a: float, b: float) -> str:
    """Perform basic arithmetic"""
    if operation == 'add':
        result = a + b
    elif operation == 'subtract':
        result = a - b
    elif operation == 'multiply':
        result = a * b
    elif operation == 'divide':
        result = a / b if b != 0 else "undefined"
    else:
        return f"Unknown operation: {operation}"

    return f"{a} {operation} {b} = {result}"

@mcp.resource("info://server")
def server_info() -> str:
    """Get server information"""
    return json.dumps({
        "name": "JACS Demo Server",
        "version": "1.0.0",
        "tools": ["echo", "calculate"]
    })

# Get ASGI app with JACS middleware
app = mcp.sse_app()

if __name__ == "__main__":
    print("Starting JACS MCP Server...")
    uvicorn.run(app, host="localhost", port=8000)
```

### MCP Client with JACS

```python
import asyncio
import jacs
from jacs.mcp import JACSMCPClient

async def main():
    # Initialize JACS
    agent = jacs.JacsAgent()
    agent.load('./jacs.client.config.json')

    # Create authenticated client
    client = JACSMCPClient("http://localhost:8000/sse")

    async with client:
        # Call echo tool
        echo_result = await client.call_tool("echo", {
            "message": "Hello from JACS client!"
        })
        print(f"Echo: {echo_result}")

        # Call calculate tool
        calc_result = await client.call_tool("calculate", {
            "operation": "multiply",
            "a": 6,
            "b": 7
        })
        print(f"Calculate: {calc_result}")

        # Read resource
        info = await client.read_resource("info://server")
        print(f"Server info: {info}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Agreements

### Creating Multi-Party Agreements

```python
import jacs
import json

def create_agreement():
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Create contract document
    contract = {
        "type": "service_agreement",
        "title": "Professional Services Agreement",
        "parties": ["Company A", "Company B"],
        "terms": "Terms and conditions here...",
        "value": 50000,
        "effectiveDate": "2024-02-01"
    }

    signed_contract = agent.create_document(json.dumps(contract))

    # Define required signers (replace with actual UUIDs)
    agent_ids = [
        "agent1-uuid-here",
        "agent2-uuid-here"
    ]

    # Create agreement
    agreement_doc = agent.create_agreement(
        signed_contract,
        agent_ids,
        question="Do you agree to the terms of this service agreement?",
        context="This is a legally binding agreement"
    )

    doc = json.loads(agreement_doc)
    print("Agreement created")
    print(f"Document ID: {doc['jacsId']}")
    print(f"Required signatures: {len(doc.get('jacsAgreement', {}).get('agentIDs', []))}")

    # Save for signing
    with open('agreement-pending.json', 'w') as f:
        f.write(agreement_doc)

    return doc

if __name__ == "__main__":
    create_agreement()
```

### Signing Agreements

```python
import jacs
import json

def sign_agreement(agreement_path: str, output_path: str) -> dict:
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Read agreement
    with open(agreement_path, 'r') as f:
        agreement_doc = f.read()

    # Sign agreement
    signed_agreement = agent.sign_agreement(agreement_doc)

    # Check status
    status_json = agent.check_agreement(signed_agreement)
    status = json.loads(status_json)

    print("Agreement signed")
    print(f"Status: {'Complete' if status.get('complete') else 'Pending'}")
    print(f"Signatures: {len(status.get('signatures', []))}")

    # Save
    with open(output_path, 'w') as f:
        f.write(signed_agreement)

    return status

if __name__ == "__main__":
    sign_agreement('./agreement-pending.json', './agreement-signed.json')
```

### Checking Agreement Status

```python
import jacs
import json

def check_agreement_status(agreement_path: str) -> dict:
    # Initialize agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    with open(agreement_path, 'r') as f:
        agreement_doc = f.read()

    status_json = agent.check_agreement(agreement_doc)
    status = json.loads(status_json)

    print("Agreement Status:")
    print(f"  Complete: {status.get('complete')}")
    print(f"  Required agents: {status.get('requiredAgents', [])}")
    print(f"  Signed by: {status.get('signedBy', [])}")
    print(f"  Missing: {status.get('missing', [])}")

    return status

if __name__ == "__main__":
    check_agreement_status('./agreement.json')
```

## Document Store

### Simple File-Based Store

```python
import jacs
import json
import os
from pathlib import Path
from typing import Optional, Dict, List

class JacsDocumentStore:
    def __init__(self, config_path: str, data_dir: str = './documents'):
        self.config_path = config_path
        self.data_dir = Path(data_dir)
        self.agent = None

    def initialize(self):
        self.agent = jacs.JacsAgent()
        self.agent.load(self.config_path)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def create(self, content: dict) -> dict:
        signed_doc = self.agent.create_document(json.dumps(content))
        doc = json.loads(signed_doc)

        filename = f"{doc['jacsId']}.json"
        filepath = self.data_dir / filename

        with open(filepath, 'w') as f:
            f.write(signed_doc)

        return {
            'id': doc['jacsId'],
            'version': doc['jacsVersion'],
            'path': str(filepath)
        }

    def get(self, document_id: str) -> Optional[dict]:
        filepath = self.data_dir / f"{document_id}.json"

        if not filepath.exists():
            return None

        with open(filepath, 'r') as f:
            return json.load(f)

    def verify(self, document_id: str) -> dict:
        filepath = self.data_dir / f"{document_id}.json"

        if not filepath.exists():
            return {'valid': False, 'error': 'Document not found'}

        with open(filepath, 'r') as f:
            doc_string = f.read()

        is_valid = self.agent.verify_document(doc_string)
        return {'valid': is_valid, 'document': json.loads(doc_string)}

    def list(self) -> List[str]:
        return [
            f.stem for f in self.data_dir.glob('*.json')
        ]

if __name__ == "__main__":
    store = JacsDocumentStore('./jacs.config.json')
    store.initialize()

    # Create document
    result = store.create({
        'type': 'note',
        'title': 'Meeting Notes',
        'content': 'Discussed project timeline...'
    })
    print(f"Created: {result['id']}")

    # Verify document
    verification = store.verify(result['id'])
    print(f"Valid: {verification['valid']}")

    # List all documents
    docs = store.list()
    print(f"Documents: {docs}")
```

## Batch Processing

### Batch Document Creator

```python
import jacs
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

class BatchDocumentProcessor:
    def __init__(self, config_path: str):
        self.config_path = config_path

    def create_documents(self, documents: list, output_dir: str) -> list:
        """Create multiple signed documents"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        results = []

        # Initialize agent
        agent = jacs.JacsAgent()
        agent.load(self.config_path)

        for i, content in enumerate(documents):
            try:
                signed_doc = agent.create_document(json.dumps(content))
                doc = json.loads(signed_doc)

                filename = f"{doc['jacsId']}.json"
                filepath = output_path / filename

                with open(filepath, 'w') as f:
                    f.write(signed_doc)

                results.append({
                    'success': True,
                    'index': i,
                    'id': doc['jacsId'],
                    'path': str(filepath)
                })
            except Exception as e:
                results.append({
                    'success': False,
                    'index': i,
                    'error': str(e)
                })

        return results

    def verify_documents(self, input_dir: str) -> list:
        """Verify all documents in a directory"""
        input_path = Path(input_dir)

        # Initialize agent
        agent = jacs.JacsAgent()
        agent.load(self.config_path)

        results = []

        for filepath in input_path.glob('*.json'):
            try:
                with open(filepath, 'r') as f:
                    doc_string = f.read()

                is_valid = agent.verify_document(doc_string)
                doc = json.loads(doc_string)

                results.append({
                    'file': filepath.name,
                    'valid': is_valid,
                    'id': doc.get('jacsId')
                })
            except Exception as e:
                results.append({
                    'file': filepath.name,
                    'valid': False,
                    'error': str(e)
                })

        return results

if __name__ == "__main__":
    processor = BatchDocumentProcessor('./jacs.config.json')

    # Create batch of documents
    documents = [
        {'type': 'invoice', 'number': f'INV-{i:03d}', 'amount': i * 100}
        for i in range(1, 11)
    ]

    results = processor.create_documents(documents, './batch-output')

    success_count = sum(1 for r in results if r['success'])
    print(f"Created {success_count}/{len(documents)} documents")

    # Verify all documents
    verification_results = processor.verify_documents('./batch-output')

    valid_count = sum(1 for r in verification_results if r['valid'])
    print(f"Valid: {valid_count}/{len(verification_results)} documents")
```

## Testing

### Pytest Setup

```python
# tests/test_jacs.py
import pytest
import jacs
import json
import tempfile
import shutil
from pathlib import Path

@pytest.fixture
def jacs_agent():
    """Create a test JACS agent with temporary directories"""
    temp_dir = tempfile.mkdtemp()
    data_dir = Path(temp_dir) / 'data'
    key_dir = Path(temp_dir) / 'keys'

    data_dir.mkdir()
    key_dir.mkdir()

    config = {
        'jacs_data_directory': str(data_dir),
        'jacs_key_directory': str(key_dir),
        'jacs_agent_key_algorithm': 'ring-Ed25519',
        'jacs_default_storage': 'fs'
    }

    config_path = Path(temp_dir) / 'jacs.config.json'
    with open(config_path, 'w') as f:
        json.dump(config, f)

    agent = jacs.JacsAgent()
    agent.load(str(config_path))

    yield agent

    shutil.rmtree(temp_dir)

class TestDocumentOperations:
    def test_create_document(self, jacs_agent):
        content = {'title': 'Test Document', 'value': 42}
        signed_doc = jacs_agent.create_document(json.dumps(content))
        doc = json.loads(signed_doc)

        assert 'jacsId' in doc
        assert 'jacsVersion' in doc
        assert 'jacsSignature' in doc
        assert doc['title'] == 'Test Document'

    def test_verify_valid_document(self, jacs_agent):
        content = {'title': 'Verify Test'}
        signed_doc = jacs_agent.create_document(json.dumps(content))

        is_valid = jacs_agent.verify_document(signed_doc)
        assert is_valid is True

    def test_detect_tampered_document(self, jacs_agent):
        content = {'title': 'Tamper Test'}
        signed_doc = jacs_agent.create_document(json.dumps(content))

        # Tamper with document
        doc = json.loads(signed_doc)
        doc['title'] = 'Modified Title'
        tampered_doc = json.dumps(doc)

        is_valid = jacs_agent.verify_document(tampered_doc)
        assert is_valid is False

    def test_different_content_different_signatures(self, jacs_agent):
        doc1 = jacs_agent.create_document(json.dumps({'a': 1}))
        doc2 = jacs_agent.create_document(json.dumps({'a': 2}))

        parsed1 = json.loads(doc1)
        parsed2 = json.loads(doc2)

        sig1 = parsed1['jacsSignature']['signature']
        sig2 = parsed2['jacsSignature']['signature']

        assert sig1 != sig2
```

## Error Handling

### Robust Error Handling Pattern

```python
import jacs
import json
from typing import Optional

class JacsError(Exception):
    def __init__(self, message: str, code: str, details: dict = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

def robust_create_document(config_path: str, content: dict) -> dict:
    """Create a document with comprehensive error handling"""
    try:
        agent = jacs.JacsAgent()
        agent.load(config_path)
    except FileNotFoundError:
        raise JacsError(
            "Configuration file not found",
            "CONFIG_NOT_FOUND",
            {"path": config_path}
        )
    except Exception as e:
        raise JacsError(
            "Failed to initialize JACS agent",
            "INIT_ERROR",
            {"original_error": str(e)}
        )

    try:
        signed_doc = agent.create_document(json.dumps(content))
        return json.loads(signed_doc)
    except Exception as e:
        raise JacsError(
            "Failed to create document",
            "CREATE_ERROR",
            {"original_error": str(e), "content": content}
        )

def robust_verify_document(config_path: str, doc_string: str) -> dict:
    """Verify a document with comprehensive error handling"""
    try:
        agent = jacs.JacsAgent()
        agent.load(config_path)
    except Exception as e:
        raise JacsError(
            "Failed to initialize JACS agent",
            "INIT_ERROR",
            {"original_error": str(e)}
        )

    try:
        is_valid = agent.verify_document(doc_string)
        return {"valid": is_valid}
    except Exception as e:
        raise JacsError(
            "Verification error",
            "VERIFY_ERROR",
            {"original_error": str(e)}
        )

if __name__ == "__main__":
    try:
        doc = robust_create_document('./jacs.config.json', {'title': 'Test'})
        print(f"Created: {doc['jacsId']}")
    except JacsError as e:
        print(f"JACS Error [{e.code}]: {e}")
        print(f"Details: {e.details}")
    except Exception as e:
        print(f"Unexpected error: {e}")
```

## See Also

- [Python Installation](../python/installation.md) - Setup guide
- [Python API Reference](../python/api.md) - Complete API documentation
- [Python MCP Integration](../python/mcp.md) - MCP details
