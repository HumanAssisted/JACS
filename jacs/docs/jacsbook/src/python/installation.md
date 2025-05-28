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
import json

print('JACS Python bindings loaded successfully!')

# Test basic functionality
try:
    config = {
        "jacs_data_directory": "./test_data",
        "jacs_key_directory": "./test_keys",
        "jacs_default_storage": "fs",
        "jacs_agent_key_algorithm": "Ed25519"
    }
    
    agent = jacs.Agent(config)
    print('Agent created successfully!')
except Exception as error:
    print(f'Error creating agent: {error}')
```

Run the test:
```bash
python test.py
```

## Package Structure

The `jacs` package includes several modules:

### Core Module
```python
import jacs

# Core classes
agent = jacs.Agent(config)
document = jacs.Document(data)
task = jacs.Task(config)
```

### MCP Integration
```python
from jacs.mcp import JacsMcpServer, create_jacs_middleware

# MCP server functionality
server = JacsMcpServer(config)
```

### FastMCP Integration
```python
from jacs.fastmcp import FastMcpServer, JacsTools

# Advanced MCP server with FastMCP
server = FastMcpServer()
server.add_jacs_tools()
```

## Configuration

### Basic Configuration
```python
config = {
    # Required fields
    "jacs_data_directory": "./jacs_data",      # Where documents are stored
    "jacs_key_directory": "./jacs_keys",       # Where keys are stored
    "jacs_default_storage": "fs",              # Storage backend
    "jacs_agent_key_algorithm": "Ed25519",     # Signing algorithm
    
    # Optional fields
    "jacs_agent_id_and_version": None,         # Existing agent to load
    "jacs_agent_private_key_filename": "private.pem",
    "jacs_agent_public_key_filename": "public.pem"
}
```

### Configuration File
You can also use a JSON configuration file:

```json
{
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys", 
  "jacs_default_storage": "fs",
  "jacs_agent_key_algorithm": "Ed25519"
}
```

Load the configuration:
```python
import json

with open('jacs.config.json', 'r') as f:
    config = json.load(f)

agent = jacs.Agent(config)
```

### Environment Variables

You can override configuration with environment variables:

```bash
export JACS_DATA_DIRECTORY="./production_data"
export JACS_KEY_DIRECTORY="./production_keys"
export JACS_AGENT_KEY_ALGORITHM="RSA"
```

```python
import os

config = {
    "jacs_data_directory": os.getenv("JACS_DATA_DIRECTORY", "./jacs_data"),
    "jacs_key_directory": os.getenv("JACS_KEY_DIRECTORY", "./jacs_keys"),
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": os.getenv("JACS_AGENT_KEY_ALGORITHM", "Ed25519")
}
```

## Storage Backends

### File System (Default)
```python
config = {
    "jacs_default_storage": "fs",
    "jacs_data_directory": "./jacs_data",
    "jacs_key_directory": "./jacs_keys"
}
```

### S3 Storage
```python
config = {
    "jacs_default_storage": "s3",
    "jacs_s3_bucket": "my-jacs-bucket",
    "jacs_s3_region": "us-west-2",
    "jacs_s3_prefix": "jacs/"
}
```

### Azure Blob Storage
```python
config = {
    "jacs_default_storage": "azure",
    "jacs_azure_account": "myaccount",
    "jacs_azure_container": "jacs",
    "jacs_azure_key": os.getenv("AZURE_STORAGE_KEY")
}
```

## Cryptographic Algorithms

### Ed25519 (Recommended)
```python
config = {
    "jacs_agent_key_algorithm": "Ed25519"
}
```

**Pros**: Fast, secure, small signatures
**Cons**: Newer standard, less universal support

### RSA-PSS
```python
config = {
    "jacs_agent_key_algorithm": "RSA"
}
```

**Pros**: Widely supported, proven security
**Cons**: Larger signatures, slower

### Post-Quantum (Experimental)
```python
config = {
    "jacs_agent_key_algorithm": "Dilithium"
}
```

**Pros**: Quantum-resistant
**Cons**: Experimental, large signatures

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
import os

def main():
    # Load configuration
    with open('jacs.config.json', 'r') as f:
        config = json.load(f)
    
    # Create agent
    agent = jacs.Agent(config)
    
    # Initialize if needed
    if not config.get("jacs_agent_id_and_version"):
        agent.generate_keys()
        agent_doc = agent.create_agent({
            "name": "My Python JACS Agent",
            "description": "Example Python JACS agent"
        })
        
        # Update config with agent ID
        config["jacs_agent_id_and_version"] = f"{agent_doc['jacsId']}:{agent_doc['jacsVersion']}"
        
        with open('jacs.config.json', 'w') as f:
            json.dump(config, f, indent=2)
    
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
import os

# Setup configuration
config = {
    "jacs_data_directory": "./notebook_data",
    "jacs_key_directory": "./notebook_keys", 
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": "Ed25519"
}

# Ensure directories exist
os.makedirs(config["jacs_data_directory"], exist_ok=True)
os.makedirs(config["jacs_key_directory"], exist_ok=True)

# Create agent
agent = jacs.Agent(config)

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

JACS includes type hints for better IDE support:

```python
from typing import Dict, List, Any
import jacs

# Type hints work with modern IDEs
config: Dict[str, Any] = {
    "jacs_data_directory": "./data",
    "jacs_key_directory": "./keys",
    "jacs_default_storage": "fs",
    "jacs_agent_key_algorithm": "Ed25519"
}

agent: jacs.Agent = jacs.Agent(config)
agent_doc: Dict[str, Any] = agent.create_agent({
    "name": "Typed Agent",
    "description": "Agent with type hints"
})
```

## Testing Setup

```python
# tests/test_jacs.py
import unittest
import tempfile
import os
import jacs

class TestJACS(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "jacs_data_directory": os.path.join(self.temp_dir, "data"),
            "jacs_key_directory": os.path.join(self.temp_dir, "keys"),
            "jacs_default_storage": "fs",
            "jacs_agent_key_algorithm": "Ed25519"
        }
        
        # Create directories
        os.makedirs(self.config["jacs_data_directory"])
        os.makedirs(self.config["jacs_key_directory"])
        
        self.agent = jacs.Agent(self.config)
    
    def test_agent_creation(self):
        self.agent.generate_keys()
        agent_doc = self.agent.create_agent({
            "name": "Test Agent",
            "description": "Agent for testing"
        })
        
        self.assertIn("jacsId", agent_doc)
        self.assertIn("jacsVersion", agent_doc)
        self.assertIn("name", agent_doc)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

if __name__ == "__main__":
    unittest.main()
```

## Next Steps

Now that you have JACS installed:

1. **[Basic Usage](basic-usage.md)** - Learn core JACS operations
2. **[MCP Integration](mcp.md)** - Add Model Context Protocol support
3. **[FastMCP Integration](fastmcp.md)** - Build advanced MCP servers
4. **[API Reference](api.md)** - Complete API documentation

## Examples

Check out the complete examples in the [examples directory](../examples/python.md):

- Basic agent creation and task management
- Jupyter notebook workflows
- FastMCP server implementation
- AI/ML pipeline integration 