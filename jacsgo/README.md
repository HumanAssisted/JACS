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
| `VerifyHumanApprovedDocument(bundle, expected, authority, provenance)` | Verify retained public approval evidence with independently selected context and pins |
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
a runtime dependency as well as a link dependency. Build against the vendored
library, then deploy the executable and that unchanged library together:

```bash
mkdir -p dist
go build -mod=vendor -o dist/my-app .
# macOS; use libjacsgo.so on Linux:
cp vendor/github.com/HumanAssisted/JACS/jacsgo/build/libjacsgo.dylib dist/
./dist/my-app
```

Move the pair together; the final program does not need the source checkout,
vendor tree, Rust installation, or an environment-variable loader override.
Its native-library dependency is `@loader_path/libjacsgo.dylib` on macOS, with
no RPATH, or `libjacsgo.so` with `$ORIGIN` on Linux (the executable's directory).
Neither embeds an absolute build-machine runtime path.
The operating system's normal system-library dependencies still apply; this
is a relocatable executable/library pair, not a statically linked executable.

## Semantic releases

Because `jacsgo` is a nested Go module, its source tag is
`jacsgo/vX.Y.Z`, while consumers request `@vX.Y.Z`. The release workflow rejects
a tag whose version differs from `jacsgo/lib/Cargo.toml`, publishes one native
asset per supported target plus a checksum manifest, and then builds and runs
an empty external consumer without a local `replace` directive.

The normal release profile enables `human-approval-vendored`: the existing
shared human-approval verifier with its existing OpenSSL backend bundled into
the native library. Asset names and installer steps are unchanged. Every release
target checks the library's load commands for external OpenSSL dependencies and
runs the same public-proof consumer before publication; the published-asset
consumer repeats that check through the installer. Both consumers compare the
complete canonical fixture report, reject a mismatched caller expectation, and
then check ordinary signing and verification. They relocate the executable and
unchanged library, make the build/vendor path unavailable, inspect the final
runtime search paths, and run from a different directory without loader
overrides. Missing proof support fails the
release check rather than being skipped. This configuration is not a claim that
every target has already been built or published.

Before checksumming, macOS release libraries receive the portable
`@loader_path/libjacsgo.dylib` load name and a repaired ad-hoc code signature. Consumers
reject a build-directory load name and never rewrite downloaded bytes. Ad-hoc
signing is not notarization or release-origin authentication; the published
checksums and build-provenance attestations retain those separate roles.

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
`jacsgo/build/`, which is the same layout used by the installer. The Make build
uses the native host platform; setting Go cross-compilation variables alone
does not build a matching Rust library. `CARGO_TARGET_DIR` can isolate native
and CLI build artifacts; the Make build stages the library from that exact
directory and fails if it cannot copy it.

`make test` and `make bench` supply a command-scoped loader path for Go's
temporary test executables; `make examples` copies the library beside its
example binaries. For direct `go test` or `go run` during source development,
set the loader path explicitly (from `jacsgo/`):

```bash
DYLD_LIBRARY_PATH="$PWD/build" LD_LIBRARY_PATH="$PWD/build" go test ./...
```

Use the vendored `build/` path instead when developing an external module.
This development override is not embedded in your executable or needed for
the adjacent-library deployment above.

Agreement v2 is the preferred model for new multi-agent consent workflows. It is shared with Rust, Python, Node.js, CLI, MCP, and WASM through the same JSON workflow. The older sidecar agreement helpers remain for simple countersignature metadata.

### Public human-approval verification

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

Release builds include this capability; default Cargo and `make build-rust`
source builds remain slim and return an explicit unsupported error for this
function. To enable the release verifier feature profile from the repository root:

```bash
make -C jacsgo build-rust CARGO_FEATURES=human-approval-vendored
cd jacsgo
go build ./...
DYLD_LIBRARY_PATH="$PWD/build" LD_LIBRARY_PATH="$PWD/build" \
  go test -tags human_approval -run 'TestHumanApprovedDocument|TestMethodParityAgainstFixture' .
```

The vendored backend needs a C toolchain, Perl, and make during source builds;
it does not require separately installed OpenSSL development headers/libraries.
Applications that deliberately use system OpenSSL can instead select the
`human-approval` Cargo feature and provide its development headers/libraries and
`pkg-config`. Both features call the same verifier with the same proof semantics.
Older shared libraries must be rebuilt to provide the new ABI symbol. Use a
matching released module and library, or build both from the same source checkout.

The Go tag enables the optional behavioral tests, not native compilation; the
Cargo feature and matching rebuilt shared library are both required. Default Go
tests still check that the package-level function remains available in the ABI.
CI tests both the slim and release verifier feature profiles. To run the full
feature-enabled suite locally after building, use
`make -C jacsgo test CARGO_FEATURES=human-approval-vendored GO_TEST_TAGS=human_approval`.

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
