# JACS Go Bindings

Cryptographic identity, signing, and verification for AI agents — from Go.

**Status:** Go bindings are community-maintained and use CGo. At the
2026-07-09 distribution baseline, the Go module had only a pseudo-version and
no matching native-library release. Use the full-repository source build below
until a semantic `jacsgo/vX.Y.Z` release and its assets actually exist.

`go get` alone is not sufficient because CGo also needs a version-matched Rust
shared library. After the first semantic release, the registry install contract
will be:

```bash
JACSGO_VERSION=vX.Y.Z # replace with a version that actually has jacsgo release assets
go get "github.com/HumanAssisted/JACS/jacsgo@${JACSGO_VERSION}"
go mod vendor
go run "github.com/HumanAssisted/JACS/jacsgo/cmd/jacsgo-install@${JACSGO_VERSION}" \
  -version "${JACSGO_VERSION}"
```

Vendoring is intentional: CGo links from the package-local `build/` directory,
so the installer writes the verified library to
`vendor/github.com/HumanAssisted/JACS/jacsgo/build/` without modifying Go's
read-only module cache. The installer downloads one platform library and
`jacsgo-vX.Y.Z-sha256sums.txt` from the `jacsgo/vX.Y.Z` GitHub release, applies
response-size and timeout limits, verifies SHA-256, and writes atomically.
Release libraries, the checksum manifest, and the SPDX SBOM also carry GitHub
build-provenance attestations. For independent release-origin verification,
run `gh attestation verify <downloaded-file> --repo HumanAssisted/JACS` before
installation.

If the matching semantic tag and release assets do not exist yet, these
commands fail closed. Use the full-repository source build below; a commit
pseudo-version has no corresponding native release asset.

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

## Request authentication and signed events

The instance-based `JacsSimpleAgent` carries the cross-language transport
contract. The body slice must contain the exact bytes sent on the wire:

```go
algorithm := "ed25519"
agent, _, err := jacs.EphemeralSimpleAgent(&algorithm)
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
var signed struct {
    Signature struct {
        AgentID string `json:"agentID"`
    } `json:"jacsSignature"`
}
if err := json.Unmarshal([]byte(envelope), &signed); err != nil {
    log.Fatal(err)
}
publicKey, err := agent.GetPublicKeyPEM()
if err != nil {
    log.Fatal(err)
}
keys, _ := json.Marshal(map[string]string{signed.Signature.AgentID: publicKey})
verifiedJSON, err := agent.UnwrapSignedEvent(envelope, string(keys))
if err != nil {
    log.Fatal(err)
}
fmt.Println(authorization, verifiedJSON)
```

This example additionally imports `encoding/json`. `BuildRequestAuthHeader` binds the
normalized method, absolute URL including query, SHA-256 of the exact body
bytes, audience, signer/key, issue time, and nonce. `SignResponse` emits a
`2.0.0` response envelope whose `jacs-response-v2` signature covers payload
and metadata. `UnwrapSignedEvent` rejects plain events, legacy payload-only
envelopes, unknown signers, and any mutation.

The key map must be pinned or resolved by the application's configured trust
policy. Successful verification proves possession of that key; it does not
independently establish a real-world identity.

Both `JacsAgent.BuildAuthHeader()` and `JacsSimpleAgent.BuildAuthHeader()` retain
the legacy no-argument form for source compatibility and emit a WARN because
they do not bind the request. New callers use `BuildRequestAuthHeader`; strict
deployments can reject the legacy method with
`JACS_REJECT_UNBOUND_AUTH_HEADER=true`.

Uses CGo to call the JACS Rust library via FFI. The prebuilt path does not
require Rust. Building the native library from source requires the full JACS
repository and Rust 1.97; the nested Go module alone does not contain its Rust
path dependencies.

## Planned semantic-release targets

| Go target | Release runner | Status |
|---|---|---|
| `darwin/arm64` | `macos-latest` | Configured release target; not shipped at the review baseline |
| `darwin/amd64` | `macos-14` | Configured release target; not shipped at the review baseline |
| `linux/amd64` (glibc) | `ubuntu-latest` | Configured release target; not shipped at the review baseline |
| `linux/arm64` (glibc) | `ubuntu-24.04-arm` | Configured release target; not shipped at the review baseline |
| Windows | — | No prebuilt library; unsupported by the current CGo directives |
| Linux musl/Alpine | — | No prebuilt library; build and compatibility are unverified |

`CGO_ENABLED=1` and a C toolchain are required. The installed shared library is
a runtime dependency as well as a link dependency; preserve the vendored
`build/` directory on the machine or in the container where the executable
runs.

## Semantic releases

Because `jacsgo` is a nested Go module, its source tag is
`jacsgo/vX.Y.Z`, while consumers request `@vX.Y.Z`. The release workflow rejects
a tag whose version differs from `jacsgo/lib/Cargo.toml`, publishes one native
asset per supported target plus a checksum manifest, and then builds and runs
an empty external consumer without a local `replace` directive.

Do not use an untagged commit or pseudo-version when you expect prebuilt native
installation. See [JACS releases](https://github.com/HumanAssisted/JACS/releases)
for versions that actually have jacsgo assets.

## Building from source

```bash
git clone https://github.com/HumanAssisted/JACS.git
cd JACS
# For reproducible use, pin a reviewed source commit before building.
make -C jacsgo build-rust
cd jacsgo
go build ./...
```

Linux source builds require `pkg-config`, a C toolchain, and D-Bus development
headers. Source builds place `libjacsgo.dylib` or `libjacsgo.so` in
`jacsgo/build/`, which is the same layout used by the installer.

Agreement v2 is the preferred model for new multi-agent consent workflows. It is shared with Rust, Python, Node.js, CLI, MCP, and WASM through the same JSON workflow. The older sidecar agreement helpers remain for simple countersignature metadata.

### Optional public human-approval verification

`VerifyHumanApprovedDocument(bundleJSON, expectedJSON, authorityJSON, provenanceJSON)`
returns the complete native report JSON without an agent handle, private key,
password, or key store. You may read the public bundle from disk. Supply the
expected operation/credential context and the two role-specific public-key pins
from your application's independent trust policy, never from the submitted
bundle. The authority pin authenticates the human/credential mapping; the
provenance pin authenticates the JACS document signer.

Both `current` report fields remain `"not_evaluated"`: retained proof is not live
permission to execute an action. The caller still checks current lifecycle and
session authorization, one-use execution, application/schema policy, external
media, and trusted time where needed.

This native feature is opt-in and uses the existing WebAuthn/OpenSSL dependency;
source builds need OpenSSL development headers/libraries and `pkg-config` in
addition to the prerequisites above. Default native builds of this revision
return an explicit unsupported error for this function. Older shared libraries
must be rebuilt to provide the new ABI symbol; no prebuilt optional-feature
release is promised here. From the repository root:

```bash
cargo build --release -p jacsgo --features human-approval
mkdir -p jacsgo/build
# macOS (on Linux, copy target/release/libjacsgo.so instead):
cp target/release/libjacsgo.dylib jacsgo/build/
cd jacsgo
go build ./...
go test -tags human_approval -run 'TestHumanApprovedDocument|TestMethodParityAgainstFixture' .
```

The Go tag enables the optional behavioral tests, not native compilation; the
Cargo feature and matching rebuilt shared library are both required. Default Go
tests still check that the package-level function remains available in the ABI.

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
