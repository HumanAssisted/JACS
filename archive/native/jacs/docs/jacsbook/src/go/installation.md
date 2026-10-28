# Go (`jacsgo`) Installation and Quick Start

`jacsgo` provides Go bindings for signing and verifying JACS documents in services, APIs, and agent runtimes.

Go bindings are supported native packages; Python and Node.js have broader
framework adapter coverage. For the primary verify-only MCP server, install
`jacs-cli` and run `jacs mcp`. The extended native server is `jacs-compat mcp`
from `jacs-cli-compat`; Go MCP examples are demos.

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
my-agent.example.com`, or programmatically with `jacs.Create(name, opts)` and
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

For multiple agents in one process, use `NewJacsAgent()`, then `agent.Load(path)`
and agent methods; call `agent.Close()` when done. Attestation and A2A helpers
also have package-level wrappers. Request authentication and signed-event
helpers require an agent instance; use `JacsSimpleAgent` for the shared simple
binding contract.

## Request authentication and signed events

For the cross-language simple contract, use `JacsSimpleAgent`:

```go
agent, _, err := jacs.EphemeralSimpleAgent(nil) // default pq2025
if err != nil {
	log.Fatal(err)
}
defer agent.Close()

body := []byte(`{"action":"approve"}`)
authorization, err := agent.BuildRequestAuthHeader(
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

`BuildRequestAuthHeader` binds method, absolute URL including query, exact body bytes,
audience, signer/key, issue time, and nonce. `SignResponse` creates a fully
bound `2.0.0` response envelope. Verify an incoming envelope with
`UnwrapSignedEvent(eventJSON, serverKeysJSON)`, where `serverKeysJSON` is a JSON
map from signer ID to a pinned base64 key or PEM string. Plain events, unknown
signers, legacy payload-only envelopes, and mutations return errors without
releasing data.

The key map is a configured trust decision. A valid signature proves key
possession, not a real-world identity by itself. Both `JacsAgent.BuildAuthHeader()`
and `JacsSimpleAgent.BuildAuthHeader()` retain the legacy no-argument form and
emit a warning. Use `BuildRequestAuthHeader` for v2; deployments can reject the
legacy form with `JACS_REJECT_UNBOUND_AUTH_HEADER=true`. See the
[security guide](../advanced/security.md#request-bound-http-authorization).

## Common Go Use Cases

- Sign outbound API/MCP payloads before crossing trust boundaries
- Verify inbound signed payloads before executing sensitive actions
- Sign files (`SignFile`) for portable chain-of-custody workflows
- Generate DNS TXT fingerprints (`GetDnsRecord`) for public identity verification

## MCP and HTTP Patterns

The Go repository includes runnable examples for transport-level signing:

- `archive/native/jacsgo/examples/mcp/main.go` for MCP-style request/response signing
- `archive/native/jacsgo/examples/http/` for signed HTTP client/server traffic

## Identity and Trust Notes

- JACS agent identity is key-based (`jacsId` + versioned signatures)
- Verification behavior follows the configured key-resolution order in the runtime (for example local and remote resolution modes supported by the underlying JACS core)
- DID interoperability is possible at the integration layer without requiring blockchain infrastructure

See [DNS-Based Verification](../rust/dns.md) and [DID Integration (No Blockchain Required)](../integrations/did.md).
