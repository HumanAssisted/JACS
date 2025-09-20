# JACS Go Bindings

Go bindings for JACS (JSON Agent Communication Standard), providing cryptographic signatures and data provenance for agent communications.

## Overview

The `jacsgo` module provides Go bindings for the JACS Rust library, following the same architectural patterns as `jacsnpm` (Node.js) and `jacspy` (Python). It uses CGO to interface with the Rust library compiled as a shared object.

## Features

- **Agent Management**: Load, verify, and update JACS agents
- **Document Operations**: Create, sign, verify, and update documents
- **Cryptographic Operations**: Sign and verify strings, hash data
- **Agreement Management**: Create and sign multi-party agreements
- **MCP Integration**: Support for Model Context Protocol with JACS authentication
- **Cross-Language Compatibility**: Binary data encoding compatible with Python and JavaScript bindings

## Installation

### Prerequisites

- Go 1.21 or later
- Rust 1.85 or later
- C compiler (for CGO)

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/HumanAssisted/JACS.git
cd JACS/jacsgo
```

2. Build the Rust library and Go bindings:
```bash
make build
```

This will:
- Build the Rust library (`libjacsgo.so`/`.dylib`/`.dll`)
- Verify the Go module builds correctly

### Using as a Go Module

Add to your `go.mod`:
```go
require github.com/HumanAssisted/JACS/jacsgo v0.1.0
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
    // Load JACS configuration
    err := jacs.Load("jacs.config.json")
    if err != nil {
        log.Fatalf("Failed to load JACS: %v", err)
    }
    
    // Hash a string
    hash, err := jacs.HashString("Hello, JACS!")
    if err != nil {
        log.Fatalf("Failed to hash: %v", err)
    }
    fmt.Printf("Hash: %s\n", hash)
    
    // Create and sign a document
    doc := map[string]interface{}{
        "title": "Test Document",
        "content": "This is a JACS document",
    }
    
    signedDoc, err := jacs.CreateDocument(doc, nil, nil, true, nil, nil)
    if err != nil {
        log.Fatalf("Failed to create document: %v", err)
    }
    fmt.Printf("Signed document: %s\n", signedDoc)
}
```

## API Reference

### Configuration

#### `Load(configPath string) error`
Load JACS configuration from a file.

#### `CreateConfig(config Config) (string, error)`
Create a new JACS configuration JSON string.

### Cryptographic Operations

#### `SignString(data string) (string, error)`
Sign a string using the loaded agent's private key.

#### `VerifyString(data, signatureBase64 string, publicKey []byte, publicKeyEncType string) error`
Verify a string signature.

#### `HashString(data string) (string, error)`
Hash a string using JACS hashing algorithm.

### Agent Operations

#### `SignAgent(agentString string, publicKey []byte, publicKeyEncType string) (string, error)`
Sign an external agent.

#### `VerifyAgent(agentFile *string) error`
Verify an agent's signature and hash.

#### `UpdateAgent(newAgentString string) (string, error)`
Update the current agent.

### Document Operations

#### `CreateDocument(documentString string, customSchema, outputFilename *string, noSave bool, attachments *string, embed *bool) (string, error)`
Create a new JACS document.

#### `VerifyDocument(documentString string) error`
Verify a document's hash and signature.

#### `UpdateDocument(documentKey, newDocumentString string, attachments []string, embed *bool) (string, error)`
Update an existing document.

#### `VerifySignature(documentString string, signatureField *string) error`
Verify a specific signature on a document.

### Agreement Operations

#### `CreateAgreement(documentString string, agentIDs []string, question, context, agreementFieldname *string) (string, error)`
Create an agreement for multiple agents.

#### `SignAgreement(documentString string, agreementFieldname *string) (string, error)`
Sign an agreement.

#### `CheckAgreement(documentString string, agreementFieldname *string) (string, error)`
Check the status of an agreement.

### MCP Operations

#### `SignRequest(payload interface{}) (string, error)`
Sign a request payload for MCP.

#### `VerifyResponse(documentString string) (map[string]interface{}, error)`
Verify and extract payload from a JACS response.

#### `VerifyResponseWithAgentID(documentString string) (payload map[string]interface{}, agentID string, err error)`
Verify a response and get the agent ID.

### Data Conversion

#### `EncodeBinaryData(data []byte) interface{}`
Encode binary data for cross-language compatibility.

#### `DecodeBinaryData(data interface{}) ([]byte, error)`
Decode binary data from cross-language format.

#### `ToJSON(v interface{}) (string, error)`
Convert Go value to JSON with special type handling.

#### `FromJSON(jsonStr string) (interface{}, error)`
Parse JSON and restore special types.

## Examples

### Basic Usage

See `examples/basic/` for a complete example covering:
- Configuration creation
- String hashing
- Document creation
- Binary data handling

### HTTP Integration

See `examples/http/` for client/server examples with:
- JACS middleware for HTTP handlers
- Request signing and verification
- Document creation endpoints

### MCP Integration

See `examples/mcp/` for Model Context Protocol examples:
- Wrapping MCP messages with JACS
- Request/response signing
- Transport layer integration

## Building and Testing

### Build Commands

```bash
# Build everything
make build

# Build only Rust library
make build-rust

# Build only Go module
make build-go

# Run tests
make test

# Run benchmarks
make bench

# Build examples
make examples

# Clean build artifacts
make clean
```

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run with race detector
go test -race -v ./...

# Run benchmarks
go test -bench=. -benchmem ./...
```

## Cross-Platform Support

The library supports:
- **Linux**: x64, ARM64
- **macOS**: x64 (Intel), ARM64 (Apple Silicon)
- **Windows**: x64

### Platform-Specific Building

```bash
# Build for current platform
make build

# Build for Linux (using Docker)
make build-linux

# Build for all platforms
make build-all
```

## Binary Data Compatibility

The library uses a special encoding for binary data to ensure compatibility across language bindings:

```go
// Go
data := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
encoded := jacs.EncodeBinaryData(data)
// Results in: {"__type__": "bytes", "data": "SGVsbG8="}
```

This is compatible with:
- Python: `bytes` objects
- JavaScript: `Buffer` objects

## Error Handling

The library uses typed errors for different failure scenarios:

```go
type JACSError struct {
    Code    int
    Message string
}
```

Error codes are operation-specific and documented in the error messages.

## Environment Variables

- `JACS_CONFIG`: Path to JACS configuration file
- `JACS_PRIVATE_KEY_PASSWORD`: Password for encrypted private keys

## Security Considerations

1. **Key Storage**: Private keys should be stored encrypted
2. **Configuration**: Protect configuration files containing paths to keys
3. **Memory**: Sensitive data is cleared from memory after use (handled by Rust)
4. **Verification**: Always verify signatures on untrusted data

## Troubleshooting

### Common Issues

1. **Library not found**: Ensure the Rust library is built and in the library path
2. **CGO errors**: Verify C compiler is installed and CGO is enabled
3. **Signature verification failures**: Check key compatibility and encoding

### Debug Output

Enable debug output by setting environment variables:
```bash
export RUST_LOG=debug
export JACS_DEBUG=1
```

## Contributing

1. Follow the existing code style
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all tests pass before submitting

## License

Same as JACS - Apache 2.0 with Common Clause. See the LICENSE file in the root repository.

## Related Projects

- [JACS](https://github.com/HumanAssisted/JACS) - Main JACS repository
- [jacsnpm](../jacsnpm) - Node.js bindings
- [jacspy](../jacspy) - Python bindings
