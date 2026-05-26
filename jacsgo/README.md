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
| `CreateAgreementV2(input)` | Create a standalone Agreement v2 document |
| `SignAgreementV2(doc, role)` | Sign as `signer`, `witness`, or `notary` |
| `VerifyAgreementV2(doc)` | Verify Agreement v2 hash, policy, transcript, and status |
| `ExportAgent()` | Export agent JSON for sharing |
| `Audit(opts)` | Run a security audit |

Uses CGo to call the JACS Rust library via FFI. Requires a Rust toolchain to build from source.

Agreement v2 is the preferred model for new multi-agent consent workflows. It is shared with Rust, Python, Node.js, CLI, MCP, and WASM through the same JSON workflow. The older sidecar agreement helpers remain for simple countersignature metadata.

## What's new in 0.10.0

*Why this matters:* shared markdown reviewed by multiple Go agents and signed images for AI-era provenance are now first-class — the signature is embedded in the artifact, no sidecar JSON required.

```go
package main

import (
    "errors"
    "fmt"
    "log"
    jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
    if err := jacs.Load(nil); err != nil {
        log.Fatal(err)
    }

    // Text — permissive verify (default)
    if _, err := jacs.SignText("README.md", nil); err != nil {
        log.Fatal(err)
    }
    result, _ := jacs.VerifyText("README.md", nil)
    fmt.Println("status:", result.Status) // "signed" | "missing_signature" | "malformed"

    // Hard-fail if the file isn't signed
    if _, err := jacs.VerifyText("README.md", &jacs.VerifyTextOpts{Strict: true}); err != nil {
        if errors.Is(err, jacs.ErrMissingSignature) {
            fmt.Println("not signed")
        } else {
            log.Fatal(err)
        }
    }

    // Override trust store with a directory of <signer_id>.public.pem files
    jacs.VerifyText("README.md", &jacs.VerifyTextOpts{KeyDir: "./trusted-keys/"})

    // Images
    jacs.SignImage("photo.png", "signed.png", nil)
    v, _ := jacs.VerifyImage("signed.png", nil)
    fmt.Println("status:", v.Status)

    // Extract embedded provenance payload (decoded JSON by default)
    payload, _ := jacs.ExtractMediaSignature("signed.png", nil)
    fmt.Println(string(payload))
}
```

A JACS inline signature proves "agent X signed these canonical bytes at their claimed time." It does not prove first creation or legal ownership.

See [DEVELOPMENT.md](https://github.com/HumanAssisted/JACS/blob/main/DEVELOPMENT.md) for the full API reference and build instructions.

## Links

- [JACS Documentation](https://humanassisted.github.io/JACS/)
- [Source](https://github.com/HumanAssisted/JACS)
- [Examples](./examples/)
