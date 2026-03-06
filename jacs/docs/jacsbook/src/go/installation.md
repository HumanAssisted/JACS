# Go (`jacsgo`) Installation and Quick Start

`jacsgo` provides Go bindings for signing and verifying JACS documents in services, APIs, and agent runtimes.

> Note: Go bindings are community-maintained. Python and Node.js currently have broader framework adapter coverage.

## Install

```bash
go get github.com/HumanAssisted/JACS/jacsgo
```

## Minimal Sign + Verify

```go
package main

import (
	"fmt"
	"log"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
	configPath := "./jacs.config.json"
	if err := jacs.Load(&configPath); err != nil {
		log.Fatal("initialize an agent first (for example with `jacs init`)")
	}

	signed, err := jacs.SignMessage(map[string]interface{}{
		"event":  "tool-result",
		"status": "ok",
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := jacs.Verify(signed.Raw)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Valid: %t signer=%s\n", result.Valid, result.SignerID)
}
```

## Common Go Use Cases

- Sign outbound API/MCP payloads before crossing trust boundaries
- Verify inbound signed payloads before executing sensitive actions
- Sign files (`SignFile`) for portable chain-of-custody workflows
- Generate DNS TXT fingerprints (`GetDnsRecord`) for public identity verification

## MCP and HTTP Patterns

The Go repository includes runnable examples for transport-level signing:

- `jacsgo/examples/mcp/main.go` for MCP-style request/response signing
- `jacsgo/examples/http/` for signed HTTP client/server traffic

## Identity and Trust Notes

- JACS agent identity is key-based (`jacsId` + versioned signatures)
- Verification behavior follows the configured key-resolution order in the runtime (for example local and remote resolution modes supported by the underlying JACS core)
- DID interoperability is possible at the integration layer without requiring blockchain infrastructure

See [DNS-Based Verification](../rust/dns.md) and [DID Integration (No Blockchain Required)](../integrations/did.md).
