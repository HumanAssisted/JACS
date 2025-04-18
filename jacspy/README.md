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