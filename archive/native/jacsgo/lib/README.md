# jacsgo

Rust C ABI for the supported JACS Go bindings. This crate builds the `jacsgo`
shared library consumed through CGo; Go applications use the
[Go module and installation guide](https://github.com/HumanAssisted/JACS/blob/main/archive/native/jacsgo/README.md).

`go get` alone does not install a matching native library. Use the Go installer
or build the native library from the full repository with `make build-jacsgo`.
The [release inventory](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md)
records 0.15.0 artifacts for macOS arm64/amd64 and Linux arm64/amd64. New source
changes require separate release evidence. Current source builds require Rust
1.97+, Go and a platform C toolchain.

New identities default to ML-DSA-87 (`pq2025`). Native signing and verification,
trust, agreements and optional attestation APIs share `jacs-binding-core`; this
crate owns the C ABI and memory boundary, not independent protocol semantics.

Apache-2.0. See [LICENSE-APACHE](https://github.com/HumanAssisted/JACS/blob/main/archive/native/LICENSE-APACHE).
