# Ticket: Add Optional ECH Path For JACS HTTP Clients

## Summary

Add an optional Encrypted ClientHello (ECH) path for outbound HTTPS calls in JACS.
This should be implemented as a lower-level TLS capability (rustls), wired through reqwest
client construction, and controlled by explicit config/feature flags.

## Why This Matters

JACS already uses TLS for confidentiality and integrity of request/response payloads.
However, without ECH, some handshake metadata (notably SNI-related information) can still
be visible on path.

For current JACS use cases (key fetches, schema fetches, DNS bootstrap helpers, CLI update checks),
adding an optional ECH path improves metadata privacy without changing JACS document formats
or signing semantics.

## Scope

### In Scope

- Add a central HTTP client builder in JACS so all reqwest clients are configured in one place.
- Add optional ECH configuration and runtime behavior.
- Keep default behavior backward compatible (ECH off by default).
- Add tests for mode handling, fallback behavior, and config wiring.
- Document operational caveats.

### Out of Scope

- Making ECH mandatory everywhere.
- Replacing reqwest entirely.
- Changing JACS document schema/signature formats.

## Current Call Sites To Migrate

Migrate these direct client builders to a shared helper:

- `jacs/src/agent/loaders.rs` (currently `reqwest::blocking::Client::builder()`)
- `jacs/src/bin/cli.rs` (multiple blocking client builders)
- `jacs/src/dns/bootstrap.rs` (blocking client builder)
- `jacs/src/schema/utils.rs` (blocking client builder)

## Design

### 1) Centralize client creation

Add a module, e.g.:

- `jacs/src/net/http_client.rs`

Expose:

- `build_blocking_client(purpose: HttpPurpose) -> Result<reqwest::blocking::Client, JacsError>`

Where `HttpPurpose` allows per-call defaults (timeouts/user-agent) while preserving one TLS policy.

### 2) Add config knobs

Add config fields (plus env var support) with conservative defaults:

- `jacs_tls_ech_mode`: `disabled | try | require` (default: `disabled`)
- `jacs_tls_doh_resolver_url`: optional DoH endpoint used to fetch HTTPS RR/ECH configs
- `jacs_tls_ech_allowlist`: optional host allowlist to limit rollout
- `jacs_tls_ech_fail_open`: bool (deprecated once `mode` is stable; map to `try`)

Recommended env names:

- `JACS_TLS_ECH_MODE`
- `JACS_TLS_DOH_RESOLVER_URL`
- `JACS_TLS_ECH_ALLOWLIST`

### 3) Implement TLS backend wiring

Implementation steps:

1. Build `rustls::ClientConfig` when ECH mode is not `disabled`.
2. Resolve ECH config for target host (HTTPS RR `ech` parameter) via configured DoH.
3. Apply ECH config with rustls APIs.
4. Inject this preconfigured TLS backend into reqwest client construction.

Behavior by mode:

- `disabled`: normal reqwest/rustls flow.
- `try`: attempt ECH; on ECH setup/handshake failure, log and fallback to non-ECH TLS.
- `require`: fail request when ECH is unavailable or fails.

### 4) Observability and safety

- Log mode + decision path at debug level.
- Do not log full target URLs or sensitive headers.
- Emit coarse counters (attempted, succeeded, fallback, failed).

### 5) Backward compatibility

- Default mode remains `disabled`.
- Existing API behavior remains unchanged unless ECH mode is explicitly enabled.
- JACS document verification/signature behavior remains untouched.

## Test Plan

### Unit Tests

- Config parsing and env override behavior for new ECH fields.
- Mode logic (`disabled`, `try`, `require`) and fallback branches.
- Allowlist matching behavior.

### Integration Tests

- Existing HTTP-dependent tests still pass with default mode.
- Add mock-path tests for:
  - `try` mode fallback on simulated ECH setup failure.
  - `require` mode hard-fail on missing ECH config.

### Regression Tests

- Verify no behavior changes in:
  - key loading over HTTPS
  - schema loading over HTTPS
  - CLI operations that call network endpoints

## Acceptance Criteria

- All direct `reqwest::blocking::Client::builder()` call sites above use the shared builder.
- ECH mode can be configured via config file and env vars.
- `disabled` mode preserves current behavior.
- `try` and `require` semantics are covered by tests.
- JACS test suite passes after migration.
- Documentation added in security/docs section describing limits and rollout guidance.

## Operational Notes

- ECH availability is endpoint- and DNS-dependent; not all domains support it.
- Reqwest does not expose first-class ECH toggles, so this must stay as advanced TLS plumbing.
- Pin/compatibility checks are required when upgrading reqwest/rustls.

## Suggested Rollout

1. Release N: ship central client builder + config plumbing + `disabled` and `try`.
2. Release N+1: enable `try` in controlled environments and collect telemetry.
3. Release N+2: optionally support `require` for strict deployments.

