# Quickstart + PQ2025 + Framework Exposure: Granular TDD Task List

Scope: implement and verify the five requested changes across Rust core, Python bindings, Node bindings, docs, and tests.

## Workstream A — Quickstart Identity Contract

Goal: `quickstart` requires `name` and `domain`, supports optional `description`, and returns/echoes config and key locations.

### A1. Contract tests first
- [x] Rust: verify `SimpleAgent::quickstart` rejects empty name/domain and returns path-rich `AgentInfo`.
- [x] Python: verify `jacs.quickstart` and `JacsClient.quickstart` reject empty name/domain.
- [x] Node: verify `jacs.quickstart` and `JacsClient.quickstart` reject missing `options.name`/`options.domain`.

### A2. Implement contract in all entry points
- [x] Rust: enforce required `name`/`domain` in `SimpleAgent::quickstart`.
- [x] Python: enforce required `name`/`domain` in simple/client quickstart wrappers.
- [x] Node: enforce required `name`/`domain` in simple/client quickstart wrappers.

### A3. Return operational file locations
- [x] Rust: `AgentInfo` includes `config_path`, key paths, directories.
- [x] Python: expose `config_path`, `public_key_path`, `private_key_path`, directories.
- [x] Node: expose `configPath`, `publicKeyPath`, `privateKeyPath`, directories.

## Workstream B — Default Algorithm Invariant (`pq2025`)

Goal: default algorithm is `pq2025` for creation/quickstart and fallback default paths.

### B1. Config/default tests first
- [x] Rust config tests updated to assert default algorithm `pq2025`.
- [x] Wrapper tests updated where default assumptions previously expected legacy defaults.

### B2. Implement defaults
- [x] Rust config defaults switched to `pq2025`.
- [x] Rust simple creation/quickstart defaults switched to `pq2025`.
- [x] Binding-core creation/quickstart defaults switched to `pq2025`.
- [x] Node wrappers quickstart/default paths switched to `pq2025`.
- [x] Python wrappers quickstart/default paths switched to `pq2025`.

### B3. DRY consolidation
- [x] Normalize wrapper fallback strings to a single consistent default (`pq2025`) per module.
- [ ] Optional follow-up: centralize algorithm default constant across all Node modules.

## Workstream C — Trust Bootstrap Surfaces (MCP + Frameworks)

Goal: expose trust bootstrap primitives for cross-agent handshake flows.

### C1. Tool/API coverage tests first
- [x] Node MCP tests: assert `jacs_share_public_key`, `jacs_share_agent`, `jacs_trust_agent_with_key` tools exist and dispatch correctly.
- [x] Node LangChain tests: assert same trust bootstrap tools exist and dispatch correctly.
- [x] Python MCP adapter tests: assert same trust bootstrap tools are registered.

### C2. Implement and export
- [x] Node MCP adapter exposes share/trust bootstrap tools.
- [x] Node LangChain toolkit exposes share/trust bootstrap tools.
- [x] Python MCP adapter exposes share/trust bootstrap tools.
- [x] Core bindings export `trust_agent_with_key` and wrappers expose client methods.

## Workstream D — Critical Gaps

Goal: remove behavior/docs mismatches that can mislead implementation users.

### D1. A2A well-known defaults
- [x] Node/Python A2A well-known generation fallback `keyAlgorithm` switched to `pq2025`.
- [x] Kept A2A JWS key default (`ring-Ed25519`) in Rust/binding-core for protocol compatibility (A2A JWS key algorithm is distinct from JACS document-signing default).

### D2. Runtime/error guidance
- [x] Node runtime error hints updated to mention `quickstart({ name, domain })`.
- [x] Docs/examples updated away from zero-arg quickstart snippets.

## Workstream E — Documentation and Examples

Goal: align jacsbook/readmes/examples to real code behavior.

### E1. jacsbook core pages
- [x] Front page (`jacsbook/src/README.md`) updated for MCP/A2A/use-case narrative, GO mention, DB integration, DID (no blockchain), encryption/post-quantum emphasis.
- [x] Quick start + simple API pages updated to required quickstart identity and path outputs.
- [x] Reference configuration/migration pages updated for `pq2025` defaults and required quickstart identity.

### E2. jacsbook guide pages
- [x] A2A guides, streaming, integration pages updated for required quickstart identity.
- [x] Multi-agent agreement examples fixed for current quickstart signature.
- [x] Express/Node examples fixed to include `name` and `domain` where quickstart is called directly.

### E3. READMEs and runnable examples
- [x] Root README quickstart and trust bootstrap handshake examples updated.
- [x] `jacspy/README.md` quickstart contract + password behavior corrected.
- [x] Python examples updated to required quickstart identity.
- [x] Node examples updated to required quickstart identity.

## Validation Matrix

- [x] Rust: targeted + feature-gated quickstart/config tests pass.
- [x] Node: build + simple/client/mcp/langchain/a2a/express/koa targeted tests pass.
- [x] Python: focused adapter/a2a/quickstart/client/simple test suites pass.
- [ ] Optional follow-up: run full cross-language fixture matrix in one pass before release cut.

## Notes

- This checklist intentionally keeps one source of truth per behavior and reuses existing adapter/client primitives instead of adding parallel APIs.
- No commits were created in this workstream; changes are review-ready in the working tree.
