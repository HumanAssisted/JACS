# Testing

This chapter covers testing strategies for applications that use JACS, including unit testing, integration testing, and mocking approaches.

## Testing Fundamentals

### Test Agent Setup

Create dedicated test configurations to isolate tests from production:

```json
// jacs.test.config.json
{
  "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
  "jacs_data_directory": "./test_data",
  "jacs_key_directory": "./test_keys",
  "jacs_agent_private_key_filename": "test_private.pem",
  "jacs_agent_public_key_filename": "test_public.pem",
  "jacs_agent_key_algorithm": "ring-Ed25519",
  "jacs_default_storage": "fs"
}
```

### Test Fixtures

Set up test fixtures before running tests:

**Python (pytest)**:

```python
import pytest
import jacs
import tempfile
import shutil

@pytest.fixture
def test_agent():
    """Create a test agent with temporary directories."""
    temp_dir = tempfile.mkdtemp()
    data_dir = f"{temp_dir}/data"
    key_dir = f"{temp_dir}/keys"

    # Initialize directories
    import os
    os.makedirs(data_dir)
    os.makedirs(key_dir)

    # Create test config
    config = {
        "jacs_data_directory": data_dir,
        "jacs_key_directory": key_dir,
        "jacs_agent_key_algorithm": "ring-Ed25519",
        "jacs_default_storage": "fs"
    }

    config_path = f"{temp_dir}/jacs.config.json"
    with open(config_path, 'w') as f:
        import json
        json.dump(config, f)

    agent = jacs.JacsAgent()
    agent.load(config_path)

    yield agent

    # Cleanup
    shutil.rmtree(temp_dir)

def test_create_document(test_agent):
    """Test document creation."""
    import json
    doc = test_agent.create_document(json.dumps({
        'title': 'Test Document'
    }))

    assert doc is not None
    parsed = json.loads(doc)
    assert 'jacsId' in parsed
    assert 'jacsSignature' in parsed
```

**Node.js (Jest)**:

```javascript
import { JacsAgent } from 'jacsnpm';
import fs from 'fs';
import path from 'path';
import os from 'os';

describe('JACS Document Tests', () => {
  let agent;
  let tempDir;

  beforeAll(() => {
    // Create temp directory
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jacs-test-'));
    const dataDir = path.join(tempDir, 'data');
    const keyDir = path.join(tempDir, 'keys');

    fs.mkdirSync(dataDir);
    fs.mkdirSync(keyDir);

    // Create test config
    const config = {
      jacs_data_directory: dataDir,
      jacs_key_directory: keyDir,
      jacs_agent_key_algorithm: 'ring-Ed25519',
      jacs_default_storage: 'fs'
    };

    const configPath = path.join(tempDir, 'jacs.config.json');
    fs.writeFileSync(configPath, JSON.stringify(config));

    agent = new JacsAgent();
    agent.load(configPath);
  });

  afterAll(() => {
    // Cleanup
    fs.rmSync(tempDir, { recursive: true });
  });

  test('creates a signed document', () => {
    const doc = agent.createDocument(JSON.stringify({
      title: 'Test Document'
    }));

    const parsed = JSON.parse(doc);
    expect(parsed.jacsId).toBeDefined();
    expect(parsed.jacsSignature).toBeDefined();
  });
});
```

## Unit Testing

### Testing Document Operations

```python
import pytest
import jacs
import json

def test_document_verification(test_agent):
    """Test that created documents verify correctly."""
    doc = test_agent.create_document(json.dumps({
        'content': 'Test content'
    }))

    is_valid = test_agent.verify_document(doc)
    assert is_valid is True

def test_document_tampering_detected(test_agent):
    """Test that tampered documents fail verification."""
    doc = test_agent.create_document(json.dumps({
        'content': 'Original content'
    }))

    # Tamper with the document
    parsed = json.loads(doc)
    parsed['content'] = 'Tampered content'
    tampered = json.dumps(parsed)

    is_valid = test_agent.verify_document(tampered)
    assert is_valid is False

def test_signature_verification(test_agent):
    """Test signature verification."""
    doc = test_agent.create_document(json.dumps({
        'data': 'test'
    }))

    is_valid = test_agent.verify_signature(doc)
    assert is_valid is True
```

### Testing Agreements

```python
def test_agreement_creation(test_agent):
    """Test creating a document with agreement."""
    doc = test_agent.create_document(json.dumps({
        'contract': 'Service Agreement'
    }))

    # Add agreement
    doc_with_agreement = test_agent.create_agreement(
        doc,
        ['agent-1-id', 'agent-2-id'],
        question='Do you agree to these terms?',
        context='Test agreement'
    )

    parsed = json.loads(doc_with_agreement)
    assert 'jacsAgreement' in parsed
    assert len(parsed['jacsAgreement']['agentIDs']) == 2

def test_agreement_signing(test_agent):
    """Test signing an agreement."""
    doc = test_agent.create_document(json.dumps({
        'contract': 'Test'
    }))

    agent_json = test_agent.load('./jacs.test.config.json')
    agent_data = json.loads(agent_json)
    agent_id = agent_data['jacsId']

    doc_with_agreement = test_agent.create_agreement(
        doc,
        [agent_id],
        question='Agree?'
    )

    signed = test_agent.sign_agreement(doc_with_agreement)

    status_json = test_agent.check_agreement(signed)
    status = json.loads(status_json)

    assert status['complete'] is True
```

### Testing Request/Response Signing

```python
def test_request_signing(test_agent):
    """Test signing a request payload."""
    payload = {
        'method': 'tools/call',
        'params': {'name': 'test_tool'}
    }

    signed = test_agent.sign_request(payload)
    assert signed is not None

    # Verify the signed request
    result = test_agent.verify_response(signed)
    assert result is not None
    assert 'payload' in result
```

## Integration Testing

### Testing MCP Integration

**Python**:

```python
import pytest
import asyncio
from jacs.mcp import JACSMCPServer, JACSMCPClient
from fastmcp import FastMCP

@pytest.fixture
def mcp_server(test_agent):
    """Create a test MCP server."""
    mcp = FastMCP("Test Server")

    @mcp.tool()
    def echo(text: str) -> str:
        return f"Echo: {text}"

    return JACSMCPServer(mcp)

@pytest.mark.asyncio
async def test_mcp_tool_call(mcp_server, test_agent):
    """Test calling an MCP tool with JACS authentication."""
    # This would require setting up actual server/client connection
    # For unit testing, test the signing/verification separately
    pass
```

**Node.js**:

```javascript
import { JACSExpressMiddleware } from 'jacsnpm/http';
import express from 'express';
import request from 'supertest';

describe('JACS Express Middleware', () => {
  let app;
  let agent;

  beforeAll(() => {
    app = express();
    app.use('/api', express.text({ type: '*/*' }));
    app.use('/api', JACSExpressMiddleware({
      configPath: './jacs.test.config.json'
    }));

    app.post('/api/echo', (req, res) => {
      res.send({ echo: req.jacsPayload });
    });

    agent = new JacsAgent();
    agent.load('./jacs.test.config.json');
  });

  test('accepts valid JACS requests', async () => {
    const signedRequest = agent.signRequest({
      message: 'Hello'
    });

    const response = await request(app)
      .post('/api/echo')
      .set('Content-Type', 'text/plain')
      .send(signedRequest);

    expect(response.status).toBe(200);
  });

  test('rejects invalid requests', async () => {
    const response = await request(app)
      .post('/api/echo')
      .set('Content-Type', 'text/plain')
      .send('{"invalid": "request"}');

    expect(response.status).toBe(400);
  });
});
```

### Testing HTTP Endpoints

```python
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import jacs
import json

app = FastAPI()

@app.post("/api/document")
async def create_doc(request_body: str):
    agent = jacs.JacsAgent()
    agent.load('./jacs.test.config.json')

    result = agent.verify_response(request_body)
    if result:
        # Process the verified payload
        return {"status": "success", "payload": result.get("payload")}
    return {"status": "error"}

@pytest.fixture
def client():
    return TestClient(app)

def test_endpoint_accepts_signed_request(client, test_agent):
    """Test that endpoint accepts properly signed requests."""
    signed = test_agent.sign_request({
        'action': 'create',
        'data': {'title': 'Test'}
    })

    response = client.post("/api/document", content=signed)
    assert response.status_code == 200
```

## Mocking

### Mocking JACS Agent

**Python**:

```python
from unittest.mock import Mock, patch
import json

def test_with_mocked_agent():
    """Test with a mocked JACS agent."""
    mock_agent = Mock()

    # Mock create_document to return a fake signed document
    mock_agent.create_document.return_value = json.dumps({
        'jacsId': 'mock-id',
        'jacsVersion': 'mock-version',
        'content': 'test',
        'jacsSignature': {'signature': 'mock-sig'}
    })

    # Mock verify_document to always return True
    mock_agent.verify_document.return_value = True

    # Use the mock in your tests
    doc = mock_agent.create_document(json.dumps({'content': 'test'}))
    assert mock_agent.verify_document(doc) is True
```

**Node.js**:

```javascript
// Mock for testing
const mockAgent = {
  createDocument: jest.fn().mockReturnValue(JSON.stringify({
    jacsId: 'mock-id',
    jacsVersion: 'mock-version',
    content: 'test',
    jacsSignature: { signature: 'mock-sig' }
  })),
  verifyDocument: jest.fn().mockReturnValue(true),
  signRequest: jest.fn().mockImplementation((payload) =>
    JSON.stringify({ payload, jacsSignature: { signature: 'mock' } })
  ),
  verifyResponse: jest.fn().mockImplementation((response) =>
    ({ payload: JSON.parse(response).payload })
  )
};

test('uses mocked agent', () => {
  const doc = mockAgent.createDocument(JSON.stringify({ test: true }));
  expect(mockAgent.createDocument).toHaveBeenCalled();
  expect(mockAgent.verifyDocument(doc)).toBe(true);
});
```

### Mocking MCP Transport

```javascript
// Mock transport for MCP testing
class MockTransport {
  constructor() {
    this.messages = [];
  }

  send(message) {
    this.messages.push(message);
  }

  async receive() {
    return this.messages.shift();
  }
}

test('MCP client with mock transport', async () => {
  const mockTransport = new MockTransport();
  // Use mock transport in tests
});
```

## Test Coverage

### Rust Coverage

For Rust coverage, we recommend **cargo-llvm-cov** for its cross-platform support and accuracy with cryptographic code.

**Installation:**

```bash
cargo install cargo-llvm-cov
```

**Running coverage:**

```bash
# Print coverage summary to stdout
cargo llvm-cov

# Generate and open HTML report in browser
cargo llvm-cov --open

# With specific features enabled
cargo llvm-cov --features cli

# Export LCOV format for CI integration
cargo llvm-cov --lcov --output-path lcov.info
```

**Why cargo-llvm-cov?**

| Factor | cargo-llvm-cov | tarpaulin |
|--------|---------------|-----------|
| Platform support | Linux, macOS, Windows | Linux primarily |
| Accuracy | LLVM source-based (highly accurate) | Ptrace-based (some inaccuracies) |
| Coverage types | Line, region, branch | Line primarily |

For complete Rust coverage documentation, see [COVERAGE.md](https://github.com/HumanAssisted/JACS/blob/main/COVERAGE.md).

### Python Coverage

```bash
# Run tests with coverage
pytest --cov=myapp --cov-report=html tests/

# View coverage report
open htmlcov/index.html
```

### Node.js Coverage

```bash
# Run tests with coverage
npm test -- --coverage

# Or with Jest directly
jest --coverage
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm install

      - name: Generate test keys
        run: |
          mkdir -p test_keys test_data
          # Generate test keys (implementation depends on your setup)

      - name: Run tests
        run: npm test

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Test Environment Variables

```bash
# Set test environment
export JACS_TEST_MODE=1
export JACS_TEST_CONFIG=./jacs.test.config.json
```

## RAII Test Fixtures (Rust)

For Rust tests that modify global state (environment variables, file system, etc.), use RAII guards to ensure cleanup even on panic. This pattern is essential for test isolation and reliability.

### TrustTestGuard Pattern

The JACS codebase uses a `TrustTestGuard` pattern for tests that modify the HOME environment variable:

```rust
use std::env;
use tempfile::TempDir;

/// RAII guard for test isolation that ensures HOME is restored even on panic.
struct TrustTestGuard {
    _temp_dir: TempDir,
    original_home: Option<String>,
}

impl TrustTestGuard {
    fn new() -> Self {
        // Save original HOME before modifying
        let original_home = env::var("HOME").ok();

        let temp_dir = TempDir::new().expect("Failed to create temp directory");

        // SAFETY: Only used in #[serial] tests - no concurrent access
        unsafe {
            env::set_var("HOME", temp_dir.path().to_str().unwrap());
        }

        Self {
            _temp_dir: temp_dir,
            original_home,
        }
    }
}

impl Drop for TrustTestGuard {
    fn drop(&mut self) {
        // Restore original HOME even during panic unwinding
        unsafe {
            match &self.original_home {
                Some(home) => env::set_var("HOME", home),
                None => env::remove_var("HOME"),
            }
        }
    }
}

// Usage in tests:
#[test]
#[serial]  // Use serial_test crate to prevent parallel execution
fn test_with_isolated_home() {
    let _guard = TrustTestGuard::new();  // Setup

    // Test code here - HOME points to temp directory

    // Guard automatically restores HOME on drop, even if test panics
}
```

**Key benefits:**

- **Panic safety**: Cleanup runs even if the test panics
- **No manual cleanup**: Drop trait handles restoration automatically
- **Environment isolation**: Each test gets a fresh temporary directory
- **Composable**: Multiple guards can be combined for complex setups

## Property-Based Testing

For cryptographic code, property-based testing helps verify invariants that hold across many random inputs. We recommend [proptest](https://crates.io/crates/proptest) for Rust.

### Key Properties to Test

1. **Round-trip**: Sign then verify should always succeed
2. **Tamper detection**: Modified content should fail verification
3. **Key independence**: Different keys produce different signatures

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn signature_roundtrip(content in ".*") {
        let signed = sign_content(&content)?;
        prop_assert!(verify_signature(&signed).is_ok());
    }

    #[test]
    fn tamper_detection(content in ".*", tamper_pos in 0usize..1000) {
        let signed = sign_content(&content)?;
        let tampered = tamper_at_position(&signed, tamper_pos);
        prop_assert!(verify_signature(&tampered).is_err());
    }
}
```

## Fuzzing

Fuzz testing is recommended for parsing and decoding functions to discover edge cases and potential security issues.

### Recommended Tool: cargo-fuzz

```bash
# Install
cargo install cargo-fuzz

# Create a fuzz target
cargo fuzz init
cargo fuzz add base64_decode

# Run fuzzing
cargo +nightly fuzz run base64_decode
```

### Priority Fuzz Targets for JACS

1. **Base64 decoding** - Handles untrusted input from signatures
2. **Agent JSON parsing** - Complex nested structures
3. **Document validation** - Schema compliance checking
4. **Timestamp parsing** - Date/time format handling

Fuzzing documentation will be expanded as fuzz targets are added to the JACS test suite.

## Best Practices

### 1. Isolate Tests

- Use separate test configurations
- Create temporary directories for each test run
- Clean up after tests (use RAII guards in Rust)

### 2. Test Edge Cases

```python
def test_empty_document():
    """Test handling of empty documents."""
    with pytest.raises(Exception):
        test_agent.create_document('')

def test_invalid_json():
    """Test handling of invalid JSON."""
    with pytest.raises(Exception):
        test_agent.create_document('not json')

def test_large_document():
    """Test handling of large documents."""
    large_content = 'x' * 1000000
    doc = test_agent.create_document(json.dumps({
        'content': large_content
    }))
    assert doc is not None
```

### 3. Test Security Properties

```python
def test_signature_changes_with_content():
    """Verify different content produces different signatures."""
    doc1 = test_agent.create_document(json.dumps({'a': 1}))
    doc2 = test_agent.create_document(json.dumps({'a': 2}))

    sig1 = json.loads(doc1)['jacsSignature']['signature']
    sig2 = json.loads(doc2)['jacsSignature']['signature']

    assert sig1 != sig2
```

### 4. Test Error Handling

```python
def test_verify_invalid_signature():
    """Test that invalid signatures are rejected."""
    doc = test_agent.create_document(json.dumps({'data': 'test'}))
    parsed = json.loads(doc)

    # Corrupt the signature
    parsed['jacsSignature']['signature'] = 'invalid'
    corrupted = json.dumps(parsed)

    assert test_agent.verify_document(corrupted) is False
```

## See Also

- [Python API Reference](../python/api.md) - API documentation
- [Node.js API Reference](../nodejs/api.md) - API documentation
- [Security Model](security.md) - Security testing considerations
