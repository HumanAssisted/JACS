# JACS contributor instructions

JACS is a portable cryptographic primitive. The active Cargo workspace contains exactly jacs-core, jacs-wasm, jacs-mobile, jacs-mcp and jacs-cli. Do not reintroduce archived native integrations into their dependency graph. Preserve licenses and unpublished compatibility source in archive/native; its AGENTS.md applies to work there.

New agents default to pq2025 (ML-DSA-87). Never fall back to a classical algorithm after an error. Secure Enclave/Keystore custody of a software PQ key is distinct from native hardware PQ signing. ES256 remains explicit compatibility only.

Keep crypto, canonicalization, identity updates and envelope validation in jacs-core with no I/O. Thin platform boundaries manage prompts, cancellation, encrypted persistence, transport and error translation. Use zeroizing secret owners and reject stale lifecycle completions. Never expose plaintext private keys or passwords in logs, command arguments, MCP tool parameters, or persistent stores.

The jacs CLI is the single binary (`cargo install jacs-cli`); MCP starts via `jacs mcp` and is verify-only by default. Initialize tracing at the host boundary and route it to stderr; stdio stdout is protocol-only. Keep CLI/MCP contract tests aligned with the actual focused surface, and preserve canonical compatibility fixtures.

Validate affected behavior with focused tests, then required workspace/browser/mobile gates. Run cargo fmt on files touched. Use make check for dependency, release, licensing, notices and security-policy checks. Release order is jacs-core, jacs-mcp, jacs-cli; keep exact candidate verification, registry checksums, audit gates, SBOMs and provenance. Source changes must not be represented as already published releases.

Make changes small and reversible. Do not remove archived source or relicense it. Keep official proprietary HAI API/application code outside this public repository. Actual API endpoints and app integration are a separate task.

## Worktrees and disk space

When creating or reusing a worktree, follow [shared Rust cache setup](README.md#shared-rust-cache-for-local-worktrees):

1. Check disk headroom with `df -h` for the worktree parent and cache filesystem before checkout and substantial builds/tests. Inspect relevant target sizes when needed; `du` can count APFS shared blocks repeatedly. Reclaim disposable outputs or reduce unnecessary build scope if space is insufficient, then complete required verification.
2. Before the first Rust build, run `make rust-cache-preview` and, if installed, `kache doctor` from the affected Cargo directory. If the binary or user Cargo wrapper is missing and preview reports no conflicts, run `make rust-cache-setup`, then `make rust-cache-smoke`. Setup is once per user/Cargo home, not per worktree; reuse an existing working setup, including one configured from hai. Resolve wrapper/config conflicts instead of silently starting a large uncached build.
3. Share the cache while keeping both target and intermediate build directories separate for concurrent worktrees. Check `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR`, `CARGO_BUILD_BUILD_DIR`, and inherited/repo Cargo settings. Never copy or symlink another worktree's targets or copy its absolute target configuration. Keep cache and worktrees on the same filesystem where possible. Avoid duplicate profiles and parallel full suites that consume unnecessary disk.
4. Setup does not reclaim old targets, and the 10 GiB retention setting is not a hard disk quota. Preview cleanup, stop the relevant builds, and remove only task-owned disposable outputs or targets confirmed unused. Preserve other worktrees, tracked files and source. Clean up temporary builds created for the task when finished.
5. The smoke check qualifies basic cache behavior, not JACS cryptography, native bindings, mobile/WASM or release builds. Preserve the required checks for the affected surface; do not change features, toolchains or release safeguards to increase cache hits.
