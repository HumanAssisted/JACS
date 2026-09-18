# Developing the portable workspace

Use the toolchain in `rust-toolchain.toml`. `make test` runs all active workspace tests, including PQ. `make check` validates the resolved dependency boundary, source versions, license consistency, notices and security policies. Browser and mobile commands are documented in their crate READMEs; GitHub CI additionally uses Android and Apple SDKs.

The active CLI and MCP own host I/O only. They must use the shared encrypted vault in `jacs-mcp`; never copy the signing/envelope implementation out of `jacs-core`. Keep stdout for command results or stdio JSON-RPC and diagnostics on stderr. MCP defaults to verify-only; local signing requires a fixed startup vault and startup-injected passwords. No caller-controlled MCP filesystem paths or unlocking secrets are accepted.

Archived code lives in an independent `archive/native` workspace with a separate lock and `publish = false`. It can depend on active `jacs-core`; the reverse is forbidden by `scripts/check_workspace_boundary.py`. Compatibility fixtures consumed by core and WASM are in `tests/fixtures/native_compat`, independent of archived executable code. The archive README documents the native HAI compatibility build.

Do not generate or check in real keys, passphrases or private API implementation. Never claim a simulator proves real-device biometric enrollment or secure-hardware behavior. Publishing packages, merging, and deploying require their own explicit authorization.
