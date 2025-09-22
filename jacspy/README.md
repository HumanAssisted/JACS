# JACS Python Library

Python bindings for JACS (JSON Agent Communication Standard) with A2A protocol support.

```
pip install jacs
```

## Quick Start

```python
import jacs

# Load JACS configuration
jacs.load("jacs.config.json")

# Sign and verify documents
signed_doc = jacs.sign_request({"data": "value"})
is_valid = jacs.verify_request(signed_doc)
```

## A2A Protocol Integration

JACS Python includes support for Google's A2A (Agent-to-Agent) protocol:

```python
from jacs.a2a import JACSA2AIntegration

# Initialize A2A integration
a2a = JACSA2AIntegration("jacs.config.json")

# Export JACS agent to A2A Agent Card
agent_card = a2a.export_agent_card(agent_data)

# Wrap A2A artifacts with JACS provenance
wrapped = a2a.wrap_artifact_with_provenance(artifact, "task")

# Verify wrapped artifacts
result = a2a.verify_wrapped_artifact(wrapped)

# Create chain of custody for workflows
chain = a2a.create_chain_of_custody([wrapped1, wrapped2, wrapped3])
```

See [examples/fastmcp/a2a_agent_server.py](./examples/fastmcp/a2a_agent_server.py) for a complete MCP server with A2A support.

## Usage






## Development Setup

This project uses Rust for the core library and Python bindings generated via [PyO3](https://pyo3.rs/) and packaged using [maturin](https://github.com/PyO3/maturin). The [uv](https://github.com/astral-sh/uv) tool is recommended for managing Python environments and dependencies.

### Prerequisites

1.  **Rust Toolchain:** Install Rust via [rustup](https://rustup.rs/):
2.  **uv:** Install the `uv` Python package manager:
    ```bash
    # macOS / Linux
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Windows / Other methods: See https://github.com/astral-sh/uv#installation
    ```
3.  **Docker:** Required for building Linux (`manylinux`) wheels using the `make build-wheel-linux` command. Install Docker Desktop or Docker Engine for your platform.

### Setup Steps

1.  **Create and Activate Virtual Environment:**
    Use `uv` to create a virtual environment. This isolates project dependencies.
    ```bash
    uv venv
    source .venv/bin/activate  
    uv pip install maturin twine
    ```
    *Note: This project itself might not have runtime Python dependencies listed in `pyproject.toml`, but these tools are needed for the build/packaging process.*

2.  **Build Wheels using Makefile:**
    *   **macOS:**
        ```bash
        make build-wheel-mac
        ```
    *   **Linux (manylinux):** (Requires Docker running)
        ```bash
        make build-wheel-linux
        ```
    Wheels will be placed in the `dist/` directory.


### Running Tests

Rust unit tests can be run directly using `cargo`:
```bash
cargo test -- --nocapture
```
```