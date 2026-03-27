# JACS Go Bindings

Cryptographic identity, signing, and verification for AI agents — from Go.

**Note:** Go bindings are community-maintained and may not include all features available in the Rust, Python, and Node.js implementations.

```bash
go get github.com/HumanAssisted/JACS/jacsgo
```

[Full documentation](https://humanassisted.github.io/JACS/) | [Quick Start](https://humanassisted.github.io/JACS/getting-started/quick-start.html)

## Quick start

```go
package main

import (
    "fmt"
    "log"
    jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
    if err := jacs.Load(nil); err != nil {
        log.Fatal("Run: jacs quickstart --name my-agent --domain example.com")
    }

    signed, _ := jacs.SignMessage(map[string]interface{}{
        "action": "approve",
        "amount": 100,
    })

    result, _ := jacs.Verify(signed.Raw)
    fmt.Printf("Valid: %t, Signer: %s\n", result.Valid, result.SignerID)
}
```

## Core API

| Function | Description |
|----------|-------------|
| `Load(configPath)` | Load agent from config |
| `Create(name, opts)` | Create new agent with keys |
| `SignMessage(data)` | Sign any JSON data |
| `SignFile(path, embed)` | Sign a file |
| `Verify(doc)` | Verify signed document |
| `VerifyStandalone(doc, opts)` | Verify without loading an agent |
| `ExportAgent()` | Export agent JSON for sharing |
| `Audit(opts)` | Run a security audit |

Uses CGo to call the JACS Rust library via FFI. Requires a Rust toolchain to build from source.

See [DEVELOPMENT.md](https://github.com/HumanAssisted/JACS/blob/main/DEVELOPMENT.md) for the full API reference and build instructions.

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](./examples/)
