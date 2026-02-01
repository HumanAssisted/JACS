# JACS Go Bindings

Go bindings for JACS - sign and verify AI agent communications.

## Installation

```bash
go get github.com/HumanAssisted/JACS/jacsgo
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
    // Load your agent
    if err := jacs.Load(nil); err != nil {
        log.Fatal("Run: jacs create --name my-agent")
    }

    // Sign a message
    signed, _ := jacs.SignMessage(map[string]interface{}{
        "action": "approve",
        "amount": 100,
    })
    fmt.Printf("Signed: %s\n", signed.DocumentID)

    // Verify it
    result, _ := jacs.Verify(signed.Raw)
    fmt.Printf("Valid: %t\n", result.Valid)
}
```

## Core API

| Function | Description |
|----------|-------------|
| `Load(configPath)` | Load agent from config file |
| `Create(name, purpose, algo)` | Create new agent with keys |
| `VerifySelf()` | Verify agent's own integrity |
| `SignMessage(data)` | Sign any JSON data |
| `SignFile(path, embed)` | Sign a file |
| `Verify(doc)` | Verify signed document |
| `GetPublicKeyPEM()` | Get public key for sharing |

## Types

```go
// Returned from SignMessage/SignFile
type SignedDocument struct {
    Raw        string // Full JSON document
    DocumentID string // UUID
    AgentID    string // Signer's ID
    Timestamp  string // ISO 8601
}

// Returned from Verify
type VerificationResult struct {
    Valid       bool
    Data        interface{}
    SignerID    string
    Timestamp   string
    Attachments []Attachment
    Errors      []string
}
```

## Examples

### Sign and Verify

```go
// Sign data
signed, err := jacs.SignMessage(myData)
if err != nil {
    log.Fatal(err)
}

// Send signed.Raw to another party...

// Verify received document
result, err := jacs.Verify(receivedJSON)
if err != nil {
    log.Fatal(err)
}

if result.Valid {
    fmt.Printf("Signed by: %s\n", result.SignerID)
    fmt.Printf("Data: %v\n", result.Data)
}
```

### File Signing

```go
// Reference only (hash stored, content not embedded)
signed, _ := jacs.SignFile("contract.pdf", false)

// Embed content (for portable documents)
signed, _ := jacs.SignFile("contract.pdf", true)
```

## Building

Requires the Rust library. From the jacsgo directory:

```bash
make build
```

## See Also

- [JACS Documentation](https://hai.ai/jacs)
- [Examples](./examples/)
