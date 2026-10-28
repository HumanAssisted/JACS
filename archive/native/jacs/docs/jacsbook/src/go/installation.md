# Go (`jacsgo`) Installation and Quick Start

`jacsgo` provides Go bindings for signing and verifying JACS documents in services, APIs, and agent runtimes.

> Note: Go bindings are community-maintained. Python and Node.js currently have broader framework adapter coverage. For the full MCP surface, install `jacs-cli-compat` and run `jacs-compat mcp`; the Go MCP examples in the repo are demo code.

## Install

Version 0.15.0 publishes the Go module and matching macOS/Linux native
libraries. `go get` alone does not provide the CGo library. In a module that
imports `github.com/HumanAssisted/JACS/jacsgo`:

```bash
go get github.com/HumanAssisted/JACS/jacsgo@v0.15.0
go mod vendor
go run github.com/HumanAssisted/JACS/jacsgo/cmd/jacsgo-install@v0.15.0 -version v0.15.0
```

The installer writes a checksum-verified library into the vendored package's
`build/` directory. See the [Go package guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsgo/README.md)
for platform coverage, provenance and source builds. From the full repository,
`make build-jacsgo` builds the current native library. Published artifacts do
not imply that later source APIs have been released.

## Minimal Sign + Verify

Create an agent first (CLI: `jacs-compat quickstart --name my-agent --domain
my-agent.example.com`, or programmatically with `jacs.Create()` and
`JACS_PRIVATE_KEY_PASSWORD`). Then:

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
            log.Fatal("create an agent first: jacs-compat quickstart --name my-agent --domain my-agent.example.com")
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

## Request authentication and signed events

For the cross-language simple contract, use `JacsSimpleAgent`:

```go
algorithm := "ed25519"
agent, _, err := jacs.EphemeralSimpleAgent(&algorithm)
if err != nil {
	log.Fatal(err)
}
defer agent.Close()

body := []byte(`{"action":"approve"}`)
authorization, err := agent.BuildAuthHeader(
	"POST",
	"https://api.example.com/v1/jobs?mode=strict",
	body,
	"jobs-api",
)
if err != nil {
	log.Fatal(err)
}

envelope, err := agent.SignResponse(`{"decision":"allow"}`)
if err != nil {
	log.Fatal(err)
}
```

`BuildAuthHeader` binds method, absolute URL including query, exact body bytes,
audience, signer/key, issue time, and nonce. `SignResponse` creates a fully
bound `2.0.0` response envelope. Verify an incoming envelope with
`UnwrapSignedEvent(eventJSON, serverKeysJSON)`, where `serverKeysJSON` is a JSON
map from signer ID to a pinned base64 key or PEM string. Plain events, unknown
signers, legacy payload-only envelopes, and mutations return errors without
releasing data.

The key map is a configured trust decision. A valid signature proves key
possession, not a real-world identity by itself. For legacy `JacsAgent`, migrate
from the denied-by-default no-argument `BuildAuthHeader` to
`BuildRequestAuthHeader`; `JacsSimpleAgent.BuildAuthHeader` already requires the
full request context and emits v2. See the
[security guide](../advanced/security.md#request-bound-http-authorization).

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
