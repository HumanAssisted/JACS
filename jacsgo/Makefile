.PHONY: all build clean test install dev build-rust build-go examples

# Default target
all: build

# Build the complete project
build: build-rust build-go
	@echo "Build completed successfully"

# Build the Rust library
build-rust:
	@echo "Building Rust library..."
	cd lib && cargo build --release
	@mkdir -p build
	@cp lib/target/release/libjacsgo.* build/ 2>/dev/null || true
	@echo "Rust library built successfully"

# Build Go module (mainly for verification)
build-go: build-rust
	@echo "Building Go module..."
	go build -v ./...
	@echo "Go module built successfully"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd lib && cargo clean
	rm -rf build/
	go clean -cache
	@echo "Clean completed successfully"

# Run tests
test: build
	@echo "Running Rust tests..."
	cd lib && cargo test
	@echo "Running Go tests..."
	go test -v ./...
	@echo "Tests completed successfully"

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
	go build -v ./...
	@echo "Development build completed"

# Build examples
examples: build
	@echo "Building examples..."
	cd examples/basic && go build -v
	cd examples/http && go build -v
	cd examples/mcp && go build -v || echo "MCP example skipped (may require additional dependencies)"
	@echo "Examples built successfully"

# Run benchmarks
bench: build
	@echo "Running Rust benchmarks..."
	cd lib && cargo bench
	@echo "Running Go benchmarks..."
	go test -bench=. -benchmem ./...

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
