# JACS contributor instructions

JACS is a portable cryptographic primitive. The active Cargo workspace contains exactly jacs-core, jacs-wasm, jacs-mobile, jacs-mcp and jacs-cli. Do not reintroduce archived native integrations into their dependency graph. Preserve licenses and unpublished compatibility source in archive/native; its AGENTS.md applies to work there.

New agents default to pq2025 (ML-DSA-87). Never fall back to a classical algorithm after an error. Secure Enclave/Keystore custody of a software PQ key is distinct from native hardware PQ signing. ES256 remains explicit compatibility only.

Keep crypto, canonicalization, identity updates and envelope validation in jacs-core with no I/O. Thin platform boundaries manage prompts, cancellation, encrypted persistence, transport and error translation. Use zeroizing secret owners and reject stale lifecycle completions. Never expose plaintext private keys or passwords in logs, command arguments, MCP tool parameters, or persistent stores.

The jacs CLI is the single binary (`cargo install jacs-cli`); MCP starts via `jacs mcp` and is verify-only by default. Initialize tracing at the host boundary and route it to stderr; stdio stdout is protocol-only. Keep CLI/MCP contract tests aligned with the actual focused surface, and preserve canonical compatibility fixtures.

Validate affected behavior with focused tests, then required workspace/browser/mobile gates. Run cargo fmt on files touched. Use make check for dependency, release, licensing, notices and security-policy checks. Release order is jacs-core, jacs-mcp, jacs-cli; keep exact candidate verification, registry checksums, audit gates, SBOMs and provenance. Source changes must not be represented as already published releases.

Make changes small and reversible. Do not remove archived source or relicense it. Keep official proprietary HAI API/application code outside this public repository. Actual API endpoints and app integration are a separate task.
