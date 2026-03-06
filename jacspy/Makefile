.PHONY: build-jacspy build-jacspy-mac build-jacspy-linux build-wheel-mac publish-wheels build-wheel-linux test test-parallel test-python test-python-parallel

PYTEST_XDIST_WORKERS ?= auto

# =============================================================================
# Development Commands (using uv - recommended)
# =============================================================================

# Install dev dependencies with uv
setup:
	@echo "Setting up development environment with uv..."
	uv venv
	uv pip install maturin pytest pytest-asyncio pytest-xdist httpx httpx-sse

# Build and install the Rust extension for development (fast iteration)
dev:
	@echo "Building jacspy in development mode..."
	uv run maturin develop

# Run all tests
test: dev
	@echo "Running tests..."
	uv run python -m pytest tests/ -v
	@if find python/jacs -type f \( -name 'test_*.py' -o -name '*_test.py' \) -print -quit | grep -q .; then \
		uv run python -m pytest python/jacs/ -v; \
	else \
		echo "No tests found under python/jacs; skipping second pytest run."; \
	fi

# Run tests in parallel where safe.
# Cross-language fixture tests stay single-process to avoid write contention when fixtures are regenerated.
test-parallel: dev
	@echo "Running tests in parallel..."
	uv run python -m pytest tests/ -v -n $(PYTEST_XDIST_WORKERS) --dist=loadfile -k "not cross_language"
	@if [ -f tests/test_cross_language.py ]; then \
		uv run python -m pytest tests/test_cross_language.py -v; \
	fi
	@if find python/jacs -type f \( -name 'test_*.py' -o -name '*_test.py' \) -print -quit | grep -q .; then \
		uv run python -m pytest python/jacs/ -v -n $(PYTEST_XDIST_WORKERS) --dist=loadfile; \
	else \
		echo "No tests found under python/jacs; skipping second pytest run."; \
	fi

# Run Python tests only (assumes already built)
test-py:
	@echo "Running Python tests..."
	uv run python -m pytest tests/ -v

# Run HAI integration tests
test-hai: dev
	@echo "Running HAI integration tests..."
	uv run python -m pytest python/jacs/test_register_new_agent.py -v

# Verify imports work
check-imports: dev
	@echo "Checking imports..."
	uv run python -c "from jacs import JacsAgent, HaiClient; print('OK: JacsAgent, HaiClient')"
	uv run python -c "from jacs.hai import register_new_agent, verify_agent; print('OK: register_new_agent, verify_agent')"
	uv run python -c "from jacs.simple import create, load, sign_message; print('OK: simple API')"

# =============================================================================
# Build Commands (for releases)
# =============================================================================

# # Build wheel for the current macOS environment
build-wheel-mac:
	@echo "Building macOS wheel..."
	maturin build --release --out dist  # Output wheels to 'dist' directory

# Publish wheels from the 'dist' directory to PyPI
publish-wheels:
	@echo "Publishing wheels from dist/ to PyPI..."
	# export TWINE_USERNAME=__token__
	# export TWINE_PASSWORD=pypi-api-token
	maturin publish --username $$TWINE_USERNAME --password $$TWINE_PASSWORD --skip-existing dist/*.whl

# Build wheel for Linux using Docker (manylinux)
build-wheel-linux:
	@echo "Building Linux (manylinux_2_28) wheel using Docker..."
	docker buildx build --tag "jacs-build-manylinux" -f Dockerfile .
	# Run maturin inside the container to build the wheel(s)
	# Mount PWD to /io, output wheel(s) to /io/dist
	# Remove the explicit --target flag to let maturin create manylinux wheels
	docker run --rm -v "$(PWD)/..:/workspace" jacs-build-manylinux \
		bash -c "cd /workspace/jacspy && maturin build --release --out dist"
	@echo "Linux manylinux wheel(s) should be in $(PWD)/dist/"

# Detect Python prefix (can be useful for debugging, but not strictly needed for maturin)
PYTHON_PREFIX := $(shell python -c "import sys; print(sys.prefix)")

# Install the Rust extension in the current virtual environment for development
install-dev:
	@echo "Installing jacspy in development mode using maturin..."
	# This compiles the Rust code and installs it so Python can import it
	maturin develop

# Run Python tests using pytest
test-python: install-dev 
	@echo "Running Python tests with pytest..."
	 RUST_BACKTRACE=1 pytest -v tests/ -s

# Run Python tests with xdist workers for faster CI/local execution.
test-python-parallel: install-dev
	@echo "Running Python tests with pytest-xdist..."
	RUST_BACKTRACE=1 pytest -v tests/ -s -n $(PYTEST_XDIST_WORKERS) --dist=loadfile -k "not cross_language"
	@if [ -f tests/test_cross_language.py ]; then \
		RUST_BACKTRACE=1 pytest -v tests/test_cross_language.py -s; \
	fi

test-mac-wheel: build-wheel-mac
	@echo "Uninstalling any existing jacs package..."
	uv pip uninstall jacs  || true  # 
	@echo "Installing newly built macOS wheel from dist/ directory..."
	# Assuming there's only one mac wheel, otherwise be more specific
	uv pip install dist/jacs-*-macosx_*.whl
	@echo "Running Python tests against the installed wheel..."
	RUST_BACKTRACE=1 pytest -v tests/ -s
	@echo "Cleaning up installed package..."
	uv pip uninstall jacs  || true

# Clean up Python build artifacts
clean-python:
	@echo "Cleaning up Python build artifacts..."
	rm -rf build dist *.egg-info .pytest_cache tests/__pycache__ src/__pycache__ target # Add others as needed

# Target to run rust unit tests, ensuring Python linkage on macOS
test-rust:
	@echo "Attempting to run Rust tests..."
	@echo "Using Python Prefix: $(PYTHON_PREFIX)"
	# Export RUSTFLAGS using separate -C link-arg flags for the test executable
	export RUSTFLAGS="-L framework=$(PYTHON_PREFIX) -C link-arg=-framework -C link-arg=Python"; \
	cargo test -- --nocapture  

.PHONY: install-dev test-python test-python-parallel clean-python test-rust
