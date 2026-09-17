# JACS portable keys and signed JSON

JACS creates, unlocks, signs with, verifies, rotates, and transfers encrypted agent keys across Rust, browsers, Android, and iOS. New browser, mobile, CLI, and MCP agents use `pq2025` (ML-DSA-87). Algorithm changes are explicit; no automatic classical fallback occurs.

The active workspace has five crates:

| Crate | Responsibility |
| --- | --- |
| `jacs-core` | No-I/O signatures, verification, encrypted envelopes, identity updates, staged key rotation, request authentication and transfer validation |
| `jacs-wasm` | Browser/WASM handles, workers and encrypted-only local storage |
| `jacs-mobile` | UniFFI bindings and Android/iOS biometric vault/session libraries |
| `jacs-mcp` | Stdio create/sign/verify/rotate/reencrypt and encrypted import/export; verify-only by default |
| `jacs-cli` | Thin `jacs` binary, including `jacs mcp` |

The legacy native stack, database backends, email/A2A/DNS/trust/network/media integrations, and native Node/Python/Go bindings are preserved in [`archive/native`](archive/native/README.md). That separate workspace is not part of the active dependency graph and its crates cannot be published. The existing native HAI SDK can explicitly use it while migrating to the portable core. Existing licenses remain in force; moving source here does not relicense it.

## Build and use

```sh
cargo build --locked -p jacs-cli
cargo test --locked --workspace
cargo run --locked -p jacs-core --example portable_quickstart
cargo run --locked -p jacs-cli -- --help
cargo run --locked -p jacs-cli -- mcp
```

Published packages may precede this source change. See [release status](docs/release-status.md); these commands build this checkout. The distribution command remains `cargo install jacs-cli`, with one executable named `jacs`.

See the [CLI guide](jacs-cli/README.md), [MCP contract](jacs-mcp/README.md), [browser guide](jacs-wasm/README.md), and [mobile guide](jacs-mobile/README.md). Passwords are obtained from the terminal or a designated environment variable, never command arguments or MCP tool parameters. File custody uses private directories, locked atomic replacement, and encrypted material only; Windows custody refuses operations until an ACL-backed store is provided.

## Biometric custody

Android protects a random wrapping secret with a per-use, enrollment-bound, strong-biometric Keystore key. iOS stores the wrapping secret and encrypted PQ material as one biometric-only, device-local Keychain record. The platform prompt releases access; the Rust core performs PQ signatures in process. Session wrappers reject cancelled or late unlock results and clear keys when backgrounded or locked. They do not silently fall back to a device passcode.

This is software PQ signing with hardware-backed custody where supported. It is not a claim that Secure Enclave or Android Keystore signs ML-DSA. ES256 hardware callbacks remain an explicit compatibility option. See [Android](jacs-mobile/platforms/android/README.md) and [iOS](jacs-mobile/platforms/ios/README.md) for lifecycle, enrollment, recovery and device-test requirements.

Encrypted transfers bind the expected identity and registered public key, validate the source material, and immediately rewrap it for destination storage. A generated six-word transfer code has 66 bits of entropy; it is not a 128-bit PQ confidentiality claim. No relay receives the unlocking code. Production relay behavior belongs to the HAI API, outside this public primitive.

## Scope and verification

Actual HAI API endpoints and mobile app integration are deferred. Library CI tests portable PQ behavior, actual browser packages, Android AAR/iOS XCFramework assembly, lifecycle races, and simulator/emulator Keychain/Keystore policies. Real-device biometric prompts, enrollment changes, secure hardware behavior and app lifecycle integration still require physical-device acceptance testing.

Run `make check` for the active boundary, license and source policy checks. Release workflows retain audits, exact candidate checksums, SBOMs and provenance verification. See [development](DEVELOPMENT.md), [release process](RELEASING.md), and [security](SECURITY.md).
