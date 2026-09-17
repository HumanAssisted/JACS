# Go (`jacsgo`) Installation and Quick Start

`jacsgo` provides Go bindings for signing and verifying JACS documents in services, APIs, and agent runtimes.

> Note: Go bindings are community-maintained. Python and Node.js currently have broader framework adapter coverage. For the full MCP surface, install `jacs-cli` and run `jacs mcp`; the Go MCP examples in the repo are demo code.

## Install

At the 2026-07-09 distribution baseline, the Go module had only a
pseudo-version and no matching native library. `go get` alone therefore cannot
produce a linkable consumer. Build the full repository today:

```bash
git clone https://github.com/HumanAssisted/JACS.git
cd JACS
# For reproducible use, pin a reviewed source commit before building.
make -C jacsgo build-rust
cd jacsgo
go test ./...
```

After a semantic `jacsgo/vX.Y.Z` release and its checksum manifest actually
exist, use the version-matched installer documented in the
[jacsgo README](https://github.com/HumanAssisted/JACS/tree/main/jacsgo).

## Minimal Sign + Verify

Create an agent first (CLI: `jacs quickstart --name my-agent --domain
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
            log.Fatal("create an agent first: jacs quickstart --name my-agent --domain my-agent.example.com")
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
