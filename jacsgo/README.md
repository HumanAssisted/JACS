# JACS Go Bindings

**Sign it. Prove it.**

Cryptographic signatures for AI agent outputs -- so anyone can verify who said what and whether it was changed. No server. Three lines of code. Optionally register with [HAI.ai](https://hai.ai) for cross-organization key discovery.

**Note:** Go bindings are community-maintained and may not include all features available in the Python and Node.js bindings. For the most complete experience, use the Python or Node.js libraries.

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
| `Load(configPath)` | Load agent from config file |
| `Create(name, opts)` | Create new agent with keys (programmatic) |
| `VerifySelf()` | Verify agent's own integrity |
| `SignMessage(data)` | Sign any JSON data |
| `SignFile(path, embed)` | Sign a file |
| `Verify(doc)` | Verify signed document (JSON string) |
| `VerifyStandalone(doc, opts?)` | Verify without loading an agent (one-off) |
| `VerifyById(id)` | Verify a document by storage ID (`uuid:version`) |
| `RegisterWithHai(opts?)` | Register the loaded agent with HAI.ai |
| `GetDnsRecord(domain, ttl)` | Get DNS TXT record line for the agent |
| `GetWellKnownJson()` | Get well-known JSON for `/.well-known/jacs-pubkey.json` |
| `ReencryptKey(oldPw, newPw)` | Re-encrypt private key with new password |
| `ExportAgent()` | Get agent's JSON for sharing |
| `GetPublicKeyPEM()` | Get public key for sharing |
| `Audit(opts?)` | Run a read-only security audit (risks, health checks, summary) |
| `GenerateVerifyLink(doc, baseUrl)` | Generate a shareable hai.ai verification URL |

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
    Password:  os.Getenv("JACS_PASSWORD"),  // required
    Algorithm: "pq2025",                     // default; also: "ring-Ed25519", "RSA-PSS"
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

### Algorithm Deprecation Notice

The `pq-dilithium` algorithm is deprecated. Use `pq2025` (ML-DSA-87, FIPS-204) instead. `pq-dilithium` still works but emits deprecation warnings.

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

## HAI Integration

The Go bindings include a pure Go HTTP client for interacting with HAI.ai services.

### HAI Client

```go
import jacs "github.com/HumanAssisted/JACS/jacsgo"

// Create a HAI client
client := jacs.NewHaiClient("https://api.hai.ai",
    jacs.WithAPIKey("your-api-key"),
    jacs.WithTimeout(30 * time.Second))

// Test connectivity
ok, err := client.TestConnection()
if err != nil {
    log.Fatal(err)
}

// Check agent registration status
status, err := client.Status("agent-uuid")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Registered: %t\n", status.Registered)

// Register an agent (requires agent JSON)
result, err := client.RegisterWithJSON(agentJSON)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Registered with JACS ID: %s\n", result.JacsID)
```

### Fetch Remote Keys

Fetch public keys from HAI's key distribution service for signature verification:

```go
// Fetch by agent ID and version
keyInfo, err := jacs.FetchRemoteKey("agent-uuid", "latest")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Algorithm: %s\n", keyInfo.Algorithm)
fmt.Printf("Public Key Hash: %s\n", keyInfo.PublicKeyHash)

// Fetch by public key hash
keyInfo, err = jacs.FetchKeyByHash("abc123...")
if err != nil {
    log.Fatal(err)
}
```

### HAI API Reference

| Function | Description |
|----------|-------------|
| `NewHaiClient(endpoint, opts...)` | Create HAI client with options |
| `client.TestConnection()` | Verify HAI server connectivity |
| `client.Status(agentID)` | Check agent registration status |
| `client.RegisterWithJSON(json)` | Register agent with HAI |
| `client.Benchmark(agentID, suite)` | Run benchmark suite |
| `FetchRemoteKey(agentID, version)` | Fetch public key from HAI |
| `FetchKeyByHash(hash)` | Fetch public key by hash |

### HAI Types

```go
// Registration result
type RegistrationResult struct {
    AgentID     string         // Agent's unique identifier
    JacsID      string         // JACS document ID from HAI
    DNSVerified bool           // DNS verification status
    Signatures  []HaiSignature // HAI attestation signatures
}

// Registration status
type StatusResult struct {
    Registered     bool     // Whether agent is registered
    AgentID        string   // Agent's JACS ID
    RegistrationID string   // HAI registration ID
    RegisteredAt   string   // ISO 8601 timestamp
    HaiSignatures  []string // HAI signature IDs
}

// Public key info from HAI key service
type PublicKeyInfo struct {
    PublicKey     []byte // Raw public key (DER encoded)
    Algorithm     string // e.g., "ed25519", "rsa-pss-sha256"
    PublicKeyHash string // SHA-256 hash
    AgentID       string // Agent ID
    Version       string // Key version
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HAI_KEYS_BASE_URL` | Base URL for HAI key service | `https://keys.hai.ai` |

## Building

Requires the Rust library. From the jacsgo directory:

```bash
make build
```

## See Also

- [JACS Book](https://humanassisted.github.io/JACS/) - Full documentation (published book)
- [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)
- [Source](https://github.com/HumanAssisted/JACS) - GitHub repository
- [HAI.ai](https://hai.ai)
- [Examples](./examples/)
