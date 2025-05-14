.PHONY: build clean install

# Default target
all: build

# Build the project
build:
	cargo build --release
	@echo "Build completed successfully"

# Clean build artifacts
clean:
	cargo clean
	@echo "Clean completed successfully"

# Install dependencies
install:
	cargo update
	@echo "Dependencies updated successfully"

# Development build
dev:
	cargo build
	@echo "Development build completed successfully"

# Run tests
test:
	cargo test
	@echo "Tests completed successfully"
