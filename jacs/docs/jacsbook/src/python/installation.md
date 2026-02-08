# Python Installation

The JACS Python package (`jacs`) provides Python bindings to the JACS Rust library, making it easy to integrate JACS into AI/ML workflows, data science projects, and Python applications.

## Requirements

- **Python**: Version 3.10 or higher
- **pip**: For package management
- **Operating System**: Linux, macOS, or Windows with WSL
- **Architecture**: x86_64 or ARM64

## Installation

### Using pip
```bash
pip install jacs
```

### Using conda
```bash
conda install -c conda-forge jacs
```

### Using poetry
```bash
poetry add jacs
```

### Development Installation
```bash
# Clone the repository
git clone https://github.com/HumanAssisted/JACS
cd JACS/jacspy

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .
```

## Verify Installation

Create a simple test to verify everything is working:

```python
# test.py
import jacs

print('JACS Python bindings loaded successfully!')

# Test basic functionality
try:
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')
    print('Agent loaded successfully!')
except Exception as error:
    print(f'Error loading agent: {error}')
```

Run the test:
```bash
python test.py
```

## Package Structure

The `jacs` package provides Python bindings to the JACS Rust library:

### Core Module
```python
import jacs

# Create and load agent
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Utility functions
hash_value = jacs.hash_string("data to hash")
config_json = jacs.create_config(
    jacs_data_directory="./data",
    jacs_key_directory="./keys",
    jacs_agent_key_algorithm="ring-Ed25519"
)
```

### JacsAgent Methods
```python
# Create a new agent instance
agent = jacs.JacsAgent()

# Load configuration
agent.load('./jacs.config.json')

# Document operations
signed_doc = agent.create_document(json_string)
is_valid = agent.verify_document(document_string)

# Signing operations
signature = agent.sign_string("data to sign")
```

## Configuration

### Configuration File

Create a `jacs.config.json` file:

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

### Load Configuration in Python

```python
import jacs

# Create agent and load configuration
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')
```

### Programmatic Configuration

```python
import jacs

# Create a configuration JSON string programmatically
config_json = jacs.create_config(
    jacs_data_directory="./jacs_data",
    jacs_key_directory="./jacs_keys",
    jacs_agent_key_algorithm="ring-Ed25519",
    jacs_default_storage="fs"
)
```

### Environment Variables

JACS reads environment variables that override configuration file settings:

```bash
export JACS_DATA_DIRECTORY="./production_data"
export JACS_KEY_DIRECTORY="./production_keys"
export JACS_AGENT_KEY_ALGORITHM="ring-Ed25519"
export JACS_DEFAULT_STORAGE="fs"
```

## Storage Backends

Configure storage in `jacs.config.json`:

### File System (Default)
```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys"
}
```

### S3 Storage
```json
{
  "jacs_default_storage": "s3"
}
```

S3 credentials are read from standard AWS environment variables.

### Memory Storage (Testing)
```json
{
  "jacs_default_storage": "memory"
}
```

## Cryptographic Algorithms

### ring-Ed25519 (Recommended)
```json
{
  "jacs_agent_key_algorithm": "ring-Ed25519"
}
```

**Pros**: Fast, secure, small signatures
**Cons**: Requires elliptic curve support

### RSA-PSS
```json
{
  "jacs_agent_key_algorithm": "RSA-PSS"
}
```

**Pros**: Widely supported, proven security
**Cons**: Larger signatures, slower

### pq-dilithium (Post-Quantum)
```json
{
  "jacs_agent_key_algorithm": "pq-dilithium"
}
```

**Pros**: Quantum-resistant
**Cons**: Experimental, large signatures

### pq2025 (Post-Quantum Hybrid)
```json
{
  "jacs_agent_key_algorithm": "pq2025"
}
```

**Pros**: Combines ML-DSA-87 with hybrid approach
**Cons**: Newest algorithm, largest signatures

## Development Setup

### Project Structure
```
my-jacs-project/
├── requirements.txt
├── jacs.config.json
├── src/
│   ├── agent.py
│   ├── tasks.py
│   └── agreements.py
├── jacs_data/
│   ├── agents/
│   ├── tasks/
│   └── documents/
├── jacs_keys/
│   ├── private.pem
│   └── public.pem
└── tests/
    └── test_jacs.py
```

### Requirements.txt Setup
```
jacs>=0.1.0
fastapi>=0.100.0  # For FastMCP integration
uvicorn>=0.23.0   # For ASGI server
pydantic>=2.0.0   # For data validation
```

### Basic Application
```python
# src/app.py
import jacs
import json

def main():
    # Create and load agent
    agent = jacs.JacsAgent()
    agent.load('./jacs.config.json')

    # Create a document
    document_data = {
        "title": "My First Document",
        "content": "Hello from Python!"
    }

    signed_doc = agent.create_document(json.dumps(document_data))
    print('Document created')

    # Verify the document
    is_valid = agent.verify_document(signed_doc)
    print(f'Document valid: {is_valid}')

    print('JACS agent ready!')
    return agent

if __name__ == "__main__":
    agent = main()
```

## Virtual Environment Setup

### Using venv
```bash
# Create virtual environment
python -m venv jacs-env

# Activate (Linux/macOS)
source jacs-env/bin/activate

# Activate (Windows)
jacs-env\Scripts\activate

# Install JACS
pip install jacs
```

### Using conda
```bash
# Create conda environment
conda create -n jacs-env python=3.11

# Activate environment
conda activate jacs-env

# Install JACS
pip install jacs
```

### Using poetry
```bash
# Initialize poetry project
poetry init

# Add JACS dependency
poetry add jacs

# Install dependencies
poetry install

# Activate shell
poetry shell
```

## Jupyter Notebook Setup

```bash
# Install Jupyter in your JACS environment
pip install jupyter

# Start Jupyter
jupyter notebook
```

```python
# In your notebook
import jacs
import json

# Create and load agent
agent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create a simple document
doc = agent.create_document(json.dumps({
    "title": "Notebook Analysis",
    "data": [1, 2, 3, 4, 5]
}))

print("Document created!")
print("JACS ready for notebook use!")
```

## Common Issues

### Module Not Found
If you get `ModuleNotFoundError: No module named 'jacs'`:

```bash
# Check Python version
python --version  # Should be 3.10+

# Check if jacs is installed
pip list | grep jacs

# Reinstall if needed
pip uninstall jacs
pip install jacs
```

### Permission Errors
If you get permission errors accessing files:

```bash
# Check directory permissions
ls -la jacs_data/ jacs_keys/

# Fix permissions
chmod 755 jacs_data/ jacs_keys/
chmod 600 jacs_keys/*.pem
```

### Binary Compatibility
If you get binary compatibility errors:

```bash
# Update pip and reinstall
pip install --upgrade pip
pip uninstall jacs
pip install jacs --no-cache-dir
```

### Windows Issues
On Windows, you may need Visual C++ Build Tools:

```bash
# Install Visual C++ Build Tools
# Or use conda-forge
conda install -c conda-forge jacs
```

## Type Hints and IDE Support

JACS is built with Rust and PyO3, providing Python bindings:

```python
import jacs
import json

# Create agent instance
agent: jacs.JacsAgent = jacs.JacsAgent()
agent.load('./jacs.config.json')

# Create and verify documents
signed_doc: str = agent.create_document(json.dumps({"title": "Test"}))
is_valid: bool = agent.verify_document(signed_doc)
```

## Testing Setup

```python
# tests/test_jacs.py
import unittest
import jacs
import json

class TestJACS(unittest.TestCase):
    def setUp(self):
        # Requires a valid jacs.config.json file
        self.agent = jacs.JacsAgent()
        self.agent.load('./jacs.config.json')

    def test_document_creation(self):
        doc_data = {"title": "Test Document", "content": "Test content"}
        signed_doc = self.agent.create_document(json.dumps(doc_data))

        # Document should be a valid JSON string
        parsed = json.loads(signed_doc)
        self.assertIn("jacsId", parsed)
        self.assertIn("jacsSignature", parsed)

    def test_document_verification(self):
        doc_data = {"title": "Verify Test"}
        signed_doc = self.agent.create_document(json.dumps(doc_data))

        is_valid = self.agent.verify_document(signed_doc)
        self.assertTrue(is_valid)

    def test_sign_string(self):
        signature = self.agent.sign_string("test data")
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

if __name__ == "__main__":
    unittest.main()
```

## Next Steps

Now that you have JACS installed:

1. **[Basic Usage](basic-usage.md)** - Learn core JACS operations
2. **[MCP Integration](mcp.md)** - Add Model Context Protocol support
3. **[FastMCP Integration](mcp.md)** - Build advanced MCP servers
4. **[API Reference](api.md)** - Complete API documentation

## Examples

Check out the complete examples in the [examples directory](../examples/python.md):

- Basic agent creation and task management
- Jupyter notebook workflows
- FastMCP server implementation
- AI/ML pipeline integration 