.PHONY: all build clean test test-competing-cargo install dev build-rust build-go build-cli examples

# Keep the existing slim source build by default. The release verifier feature
# profile uses CARGO_FEATURES=human-approval-vendored; Go tags select proof tests.
CARGO_FEATURES ?=
GO_TEST_TAGS ?=
CARGO_FEATURE_FLAGS = $(if $(strip $(CARGO_FEATURES)),--features $(CARGO_FEATURES),)
GO_TEST_TAG_FLAGS = $(if $(strip $(GO_TEST_TAGS)),-tags $(GO_TEST_TAGS),)
# The native library, test suite and prebuilt CLI share this absolute artifact
# directory, including when a caller isolates the build with CARGO_TARGET_DIR.
RUST_TARGET_DIR := $(abspath $(if $(strip $(CARGO_TARGET_DIR)),$(CARGO_TARGET_DIR),../target))
# Source-development tests run from Go's temporary executable directories.
# This command-scoped override never becomes a deployed binary's runtime path.
GO_RUNTIME_ENV = DYLD_LIBRARY_PATH="$(abspath build)$(if $(strip $(DYLD_LIBRARY_PATH)),:$(DYLD_LIBRARY_PATH),)" LD_LIBRARY_PATH="$(abspath build)$(if $(strip $(LD_LIBRARY_PATH)),:$(LD_LIBRARY_PATH),)"
NATIVE_LIBRARY := $(if $(filter Darwin,$(shell uname -s)),libjacsgo.dylib,libjacsgo.so)

# Default target
all: build

# Build the complete project
build: build-rust build-go
	@echo "Build completed successfully"

# Build the Rust library
build-rust:
	@echo "Building Rust library..."
	cargo build --manifest-path lib/Cargo.toml --release --target-dir "$(RUST_TARGET_DIR)" $(CARGO_FEATURE_FLAGS)
	@mkdir -p build
	@set -e; case "$$(uname -s)" in \
		Darwin) library=libjacsgo.dylib ;; \
		Linux) library=libjacsgo.so ;; \
		*) echo "build-rust supports native macOS and Linux hosts only" >&2; exit 1 ;; \
	esac; \
	cp "$(RUST_TARGET_DIR)/release/$$library" "build/$$library"; \
	if [ "$$library" = libjacsgo.dylib ]; then \
		install_name_tool -id '@loader_path/libjacsgo.dylib' "build/$$library"; \
		codesign --force --sign - "build/$$library"; \
		bash scripts/check-macos-install-name.sh "build/$$library"; \
	fi
	@echo "Rust library built successfully"

# Build Go module (mainly for verification)
build-go: build-rust
	@echo "Building Go module..."
	go build -v ./...
	@echo "Go module built successfully"

# Build the CLI once for Go->Rust provenance verification. Tests execute this
# binary directly through JACS_CLI_BIN; they never start a nested Cargo build.
build-cli:
	cd .. && cargo build -p jacs-cli --bin jacs --target-dir "$(RUST_TARGET_DIR)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd lib && cargo clean
	rm -rf build/
	go clean -cache
	@echo "Clean completed successfully"

# Run tests
test: build build-cli
	@echo "Running Rust tests..."
	cd lib && cargo test --target-dir "$(RUST_TARGET_DIR)" $(CARGO_FEATURE_FLAGS)
	@echo "Running Go tests with the race detector..."
	$(GO_RUNTIME_ENV) JACS_CLI_BIN="$(RUST_TARGET_DIR)/debug/jacs" go test $(GO_TEST_TAG_FLAGS) -race -v ./...
	@echo "Tests completed successfully"

# Regression for JACS_REVIEW_ISSUE_014: the Go->Rust provenance test executes
# a prebuilt CLI directly and must finish while another real Cargo build is
# active. The script applies both the Go package timeout and the CLI's own
# CommandContext deadline, and preserves the competing build log on failure.
test-competing-cargo: build build-cli
	$(GO_RUNTIME_ENV) JACS_CLI_BIN="$(RUST_TARGET_DIR)/debug/jacs" ./scripts/test-competing-cargo.sh

# Install dependencies
install:
	@echo "Installing Rust dependencies..."
	cd lib && cargo update
	@echo "Installing Go dependencies..."
	go mod tidy
	@echo "Dependencies installed successfully"

# Development build with verbose output
dev:
	@echo "Development build..."
	cd lib && cargo build --verbose
	$(GO_RUNTIME_ENV) go build -v ./...
	@echo "Development build completed"

# Build examples
examples: build
	@echo "Building examples..."
	cd examples/basic && go build -v
	cd examples/http && go build -tags server -o server && go build -tags client -o client
	cd examples/mcp && go build -v || echo "MCP example skipped (may require additional dependencies)"
	cp "build/$(NATIVE_LIBRARY)" examples/basic/
	cp "build/$(NATIVE_LIBRARY)" examples/http/
	cp "build/$(NATIVE_LIBRARY)" examples/mcp/
	@echo "Examples built successfully"

# Run benchmarks
bench: build
	@echo "Running Rust benchmarks..."
	cd lib && cargo bench
	@echo "Running Go benchmarks..."
	$(GO_RUNTIME_ENV) go test -bench=. -benchmem ./...

# Build for Linux using Docker
build-linux:
	@echo "Building for Linux using Docker..."
	docker run --rm -v "$$(pwd):/workspace" -w /workspace/lib rust:latest \
		bash -c "cargo build --release && mkdir -p ../build && cp target/release/libjacsgo.so ../build/"
	@echo "Linux build completed"

# Build for multiple platforms
build-all: build build-linux
	@echo "All platform builds completed"

# Generate documentation
docs:
	@echo "Generating Rust documentation..."
	cd lib && cargo doc --no-deps
	@echo "Generating Go documentation..."
	go doc -all > docs.txt
	@echo "Documentation generated"

# Format code
fmt:
	@echo "Formatting Rust code..."
	cd lib && cargo fmt
	@echo "Formatting Go code..."
	go fmt ./...
	@echo "Code formatting completed"

# Lint code
lint:
	@echo "Linting Rust code..."
	cd lib && cargo clippy -- -D warnings
	@echo "Linting Go code..."
	go vet ./...
	@echo "Linting completed"

# Quick check without building
check:
	@echo "Checking Rust code..."
	cd lib && cargo check
	@echo "Checking Go code..."
	go vet ./...
	@echo "Check completed"
