# Native mobile binding ↔ browser PQ interoperability

This test exercises real ML-DSA-87 cryptography through the generated `jacs-mobile` Python UniFFI binding and the release `jacs-wasm` package running inside Chromium. It does not use a mocked signer, Python crypto implementation, or Node WASM runtime.

1. Native UniFFI creates a PQ agent, signs a challenge, and exports an encrypted key bundle.
2. Chromium imports that bundle with independently passed public-key/identity pins, verifies the native signature, signs a response, re-encrypts with a different test password, and clears its key.
3. Native UniFFI imports the browser's encrypted bundle, confirms its identity and version, verifies the browser signature, and clears its key.

Fixture files and both encrypted key bundles are generated in a temporary directory and removed in `finally`. Passwords are deliberately fixed **test-only** values; generated keys are disposable. Only status lines are logged. The local HTTP server exposes the public WASM files, never fixtures or passwords.

## Prerequisites

- A matching `jacs-mobile` host library and generated Python binding. Use `jacs-mobile/scripts/generate-bindings.sh` and the mobile build instructions.
- A release browser package at `jacs-wasm/pkg`, built with the documented WASM stack configuration (`cd jacs-wasm && wasm-pack build --target web --release . --locked && bash scripts/finalize-pkg.sh`).
- Node.js 18+, Python 3, Playwright, and a Chromium executable. Install browser dependencies separately; the harness does not install or publish anything.

```sh
node tests/portable-interop/run.mjs
```

Every external path is configurable:

| Environment variable | Default |
| --- | --- |
| `JACS_INTEROP_WASM_PKG` | `jacs-wasm/pkg` in this checkout |
| `JACS_INTEROP_MOBILE_PYTHON` | `jacs-mobile/generated/python/jacs_mobile.py` |
| `JACS_INTEROP_MOBILE_LIB` | `target/debug/libjacs_mobile.so` (platform suffix adjusted) |
| `JACS_INTEROP_PYTHON` | `CODEX_PRIMARY_RUNTIME_PYTHON`, otherwise `python3` |
| `JACS_INTEROP_PLAYWRIGHT_MODULE` | Runtime-owned Playwright when available, otherwise `playwright` |
| `JACS_INTEROP_CHROMIUM_EXECUTABLE` | Playwright's installed Chromium |
| `JACS_INTEROP_CHROMIUM_MODULE` | Optional absolute path/module specifier for `@sparticuz/chromium` |
| `JACS_INTEROP_TIMEOUT_MS` | `120000`, maximum `300000` |

For a custom Chromium distribution, set its executable and optional launch-configuration module. The harness does not disable browser web security or site isolation. It binds HTTP to loopback on an ephemeral port and runs the browser/server in the same process environment.

A pass proves native UniFFI/WASM key-envelope and signature interoperability. It does not replace Android/iOS application packaging, physical-device biometric, or hardware-keystore tests. Host UniFFI uses the same Rust mobile API, but this harness does not run on a phone.

Run `JACS_INTEROP_RECOVERY=1 node tests/portable-interop/run.mjs` for generated
128-bit recovery instead of the compatibility test passwords. This additionally
creates human identities via UniFFI, browser WASM and a real Web Worker, verifies
browser/worker identities in native UniFFI, and checks worker rejection of wrong
codes, wrong pins, malformed material, short transfer codes and locked exports.
Recovery codes exist only in mode-0600 disposable fixtures which are deleted by
the harness; none appear in status output or HTTP routes.

Recovery mode also exercises complete `signDocument` envelopes, syntax
normalization and noninteractive `verifyRecovery` read-back on native/WASM/worker.
The read-back result is public identity JSON, never an unlocked handle.

`native_document_check.rs` checks the public golden fixture and fresh core output
against archived `jacs::verification::NonSigningVerifier` plus its native checksum
implementation. Run it from a temporary standalone Cargo manifest outside this
workspace, with `jacs` pointing to `archive/native/jacs` (`default-features=false`),
`jacs-core` pointing to `jacs-core`, `serde_json="1"`, `base64="0.23"`, and a `[[bin]]`
path to that source. Use `cargo run --manifest-path <temporary-manifest> --bin
native-document-check`. Do not add archived dependencies to the active workspace.
The older signing-agent verifier checks only the historical normalized key-hash
alias; the explicit non-signing verifier supports portable raw-key hashes too.
