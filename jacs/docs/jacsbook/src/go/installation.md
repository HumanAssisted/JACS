# Go (`jacsgo`) Installation and Quick Start

`jacsgo` provides Go bindings for signing and verifying JACS documents in services, APIs, and agent runtimes.

> Note: Go bindings are community-maintained. Python and Node.js currently have broader framework adapter coverage. For full MCP surface use the Rust `jacs-mcp` server; the Go MCP examples in the repo are demo code.

## Install

```bash
go get github.com/HumanAssisted/JACS/jacsgo
```

## Minimal Sign + Verify

Create an agent first (CLI: `jacs create --name my-agent`, or programmatically with `jacs.Create()` and `JACS_PRIVATE_KEY_PASSWORD`). Then:

```go
package main

import (
	"fmt"
	"log"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
	// Load agent: nil = default ./jacs.config.json
	if err := jacs.Load(nil); err != nil {
		log.Fatal("create an agent first: jacs create --name my-agent")
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

## Programmatic agent creation

Use `jacs.Create(name, &jacs.CreateAgentOptions{...})`. Password must be set in options or via `JACS_PRIVATE_KEY_PASSWORD`. See the [jacsgo README](https://github.com/HumanAssisted/JACS/tree/main/jacsgo) for the full API table and options.

## Concurrent use

For multiple agents in one process, use `NewJacsAgent()`, then `agent.Load(path)` and agent methods; call `agent.Close()` when done. Attestation, A2A (agent cards, trust policy), and protocol helpers are available on `JacsAgent` and as package-level wrappers (see godoc or the jacsgo README).

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
