# JACS Go Bindings

**Sign it. Prove it.**

Cryptographic signatures for AI agent outputs -- so anyone can verify who said what and whether it was changed. No server. Three lines of code.

**Note:** Go bindings are community-maintained and may not include all features available in the Python and Node.js bindings. The Go MCP code in this repo is demo/example code, not a full canonical JACS MCP server. For the full MCP surface, use the Rust `jacs-mcp` server.

[Which integration should I use?](https://humanassisted.github.io/JACS/getting-started/decision-tree.html) | [Full documentation](https://humanassisted.github.io/JACS/)

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
| `Load(configPath *string)` | Load agent from config (nil = default `./jacs.config.json`) |
| `Create(name, opts)` | Create new agent with keys (programmatic) |
| `VerifySelf()` | Verify agent's own integrity |
| `SignMessage(data)` | Sign any JSON data |
| `SignFile(path, embed)` | Sign a file |
| `Verify(doc)` | Verify signed document (JSON string) |
| `VerifyStandalone(doc, opts?)` | Verify without loading an agent; opts = *VerifyOptions (KeyResolution, DataDirectory, KeyDirectory) |
| `VerifyById(id)` | Verify a document by storage ID (`uuid:version`) |
| `GetDnsRecord(domain, ttl)` | Get DNS TXT record line for the agent |
| `GetWellKnownJson()` | Get well-known JSON for `/.well-known/jacs-pubkey.json` |
| `ReencryptKey(oldPw, newPw)` | Re-encrypt private key with new password |
| `ExportAgent()` | Get agent's JSON for sharing |
| `GetPublicKeyPEM()` | Get public key for sharing |
| `Audit(opts?)` | Read-only security audit; opts = *AuditOptions (ConfigPath, RecentN) |

For concurrent use (multiple agents in one process), use `NewJacsAgent()`, then `agent.Load(path)` and agent methods (`SignRequest`, `VerifyDocument`, etc.). Call `agent.Close()` when done.

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

## Programmatic Agent Creation

```go
import jacs "github.com/HumanAssisted/JACS/jacsgo"

info, err := jacs.Create("my-agent", &jacs.CreateAgentOptions{
    Password:  os.Getenv("JACS_PRIVATE_KEY_PASSWORD"),  // required (or set env)
    Algorithm: "pq2025",                               // default; also: "ring-Ed25519", "RSA-PSS"
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created: %s\n", info.AgentID)
```

### Verify by Document ID

```go
result, err := jacs.VerifyById("550e8400-e29b-41d4-a716-446655440000:1")
if err == nil && result.Valid {
    fmt.Println("Document verified")
}
```

### Re-encrypt Private Key

```go
err := jacs.ReencryptKey("old-password-123!", "new-Str0ng-P@ss!")
```

### Password Requirements

Passwords must be at least 8 characters and include uppercase, lowercase, a digit, and a special character.

### Post-Quantum Algorithm

Use `pq2025` (ML-DSA-87, FIPS-204) for post-quantum signing.

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

## Platform Integration

For platform-level features (agent registration, key discovery, benchmarking), see the [haisdk](https://github.com/HumanAssisted/haisdk) package. Attestation, A2A (agent cards, trust policy), and protocol helpers (e.g. `BuildAuthHeader`, `CanonicalizeJson`) are available on `JacsAgent` and as package-level wrappers; see godoc.

## Building

The Go bindings use CGo to call the JACS Rust library via FFI. Requires the Rust toolchain to build from source. From the jacsgo directory:

```bash
make build
```

## See Also

- [JACS Book](https://humanassisted.github.io/JACS/) - Full documentation (published book)
- [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Source](https://github.com/HumanAssisted/JACS) - GitHub repository
- [Examples](./examples/)
