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
