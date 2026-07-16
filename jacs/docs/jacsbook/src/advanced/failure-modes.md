# Failure Modes

This page documents the error messages you will see when multi-agent agreements fail, plus the [P2 compatibility and export failure table](#p2-compatibility-and-export-failures) for operators. Each agreement scenario is validated by the chaos agreement tests in the JACS test suite.

## Partial Signing (Agent Crash)

**What happened:** An agreement was created for N agents but one or more agents never signed -- they crashed, timed out, or disconnected before calling `sign_agreement`.

**Error message:**

```
not all agents have signed: ["<unsigned-agent-id>"] { ... agreement object ... }
```

**What to do:** Identify the unsigned agent from the error, re-establish contact, and have them call `sign_agreement` on the document. The partially-signed document is still valid and can accept additional signatures -- signing is additive.

## Quorum Not Met

**What happened:** An agreement with an explicit quorum (M-of-N via `AgreementOptions`) received fewer than M signatures.

**Error message:**

```
Quorum not met: need 2 signatures, have 1 (unsigned: ["<agent-id>"])
```

**What to do:** Either collect more signatures to meet the quorum threshold, or create a new agreement with a lower quorum if appropriate. The unsigned agent IDs in the error tell you exactly who still needs to sign.

## Tampered Signature

**What happened:** A signature byte was modified after an agent signed the agreement. The cryptographic verification layer detects that the signature does not match the signed content.

**Error message:**

The exact message comes from the crypto verification layer and varies by algorithm, but it will always fail on the signature check rather than reporting missing signatures. You will not see "not all agents have signed" for this case -- the error is a cryptographic verification failure.

**What to do:** This indicates data corruption in transit or deliberate tampering. Discard the document and request a fresh copy from the signing agent. Do not attempt to re-sign a document with a corrupted signature.

## Tampered Document Body

**What happened:** The document content was modified after signatures were applied. JACS stores an integrity hash of the agreement-relevant fields at signing time, and any body modification causes a mismatch.

**Error message:**

```
Agreement verification failed: agreement hashes do not match
```

**What to do:** The document body no longer matches what the agents originally signed. Discard the modified document and go back to the last known-good version. If the modification was intentional (e.g., an amendment), create a new agreement on the updated document and collect fresh signatures from all parties.

## In-Memory Consistency After Signing

**What happened:** `sign_agreement` succeeded but `save()` was never called -- for example, a storage backend failure or process interruption before persistence.

**Error message:** None. This is not an error. After `sign_agreement` returns successfully, the signed document is immediately retrievable and verifiable from in-memory storage.

**What to do:** Retry the `save()` call to persist to disk. The in-memory state is consistent: you can retrieve the document with `get_document`, verify it with `check_agreement`, serialize it, and transfer it to other agents for additional signatures -- all without saving first.

## P2 Compatibility and Export Failures

Beyond agreements, the P2 trust model (native signing with a post-quantum
default, the ES256 compatibility key, and targeted ecosystem exports) emits structured log
events with matching Prometheus counters. This is the sysadmin fix-table:
what fired, which metric to alert on, which part of the model is involved,
and the usual fix.

Note on the Metric column: the counters exist only in builds with the
`otlp-metrics` feature enabled — it is not in the default feature set of
the `jacs` crate or of `cargo install jacs-cli`, so in a default build the
counters compile to no-ops. The log events are always emitted once a
tracing subscriber is installed (see
[Observability](../guides/observability.md)).

| Log event | Metric | Failure class | Likely fix |
|-----------|--------|---------------|------------|
| `compatibility_key_missing` (WARN) | `jacs_compatibility_export_error_total{format,reason="missing_key"}` | compatibility binding | An export was attempted (`requested_export` in the event; `format` on the metric) but the agent has no ES256 compatibility key — run `jacs agent add-compat-key`. |
| `compatibility_key_unreadable` (WARN) | — (log event only, no counter) | compatibility binding | A gate-and-enrich export (`did`, `w3c-agent-identity`) found the ES256 key state corrupt or inconsistent — `jacs.keyring.json` unparseable, or the keyring and the key files disagree (`reason` in the event). The export still succeeds in its native-only shape (a corrupt keyring must not take down DID serving), so this WARN is the only signal — inspect `jacs.keyring.json` and the `jacs.ecosystem.*` key files in the key directory. Distinct from `compatibility_key_missing`, which is the quiet never-migrated state. |
| `compatibility_binding_verify_failed` (WARN) | `jacs_compatibility_binding_verify_failed_total{reason}` | compatibility binding | The native-root-signed binding no longer verifies (`jacs_id` + compat `kid` in the event) — re-issue after key rotation (`jacs agent issue-compat-binding`) and check `expiresAt`. Fixed `reason` values: `schema_invalid` (also covers a `jacsSha256` content-hash mismatch — the document lies about itself), `signature_invalid`, `rotated_root`, `root_kid_mismatch`, `compat_kid_mismatch`, `jwk_mismatch`, `identity_mismatch`, `version_mismatch` (identity discovery safely reissues an otherwise-authentic same-root stale-version binding), `superseded` (an older validly-signed binding was restored over a re-issue; latest `issuedAt` wins), and `expired` (also an unparseable `expiresAt`, which fails closed). |
| `content_export_scope_denied` (WARN) | `jacs_content_export_scope_denied_total{format}` | ecosystem export | The binding (`binding_hash` in the event) lacks the requested scope (`ap2-mandate`, `agreement-vc` are never auto-issued) — re-issue the binding with that scope; the current native root signs the grant. |
| `compatibility_binding_created` (INFO) | — (log event only, no counter) | compatibility binding | Success, not a failure — the current native root (re-)issued the compatibility key binding (`jacs_id`, compat `kid`, `binding_hash`, and granted `scopes` in the event). Expect one per `jacs agent issue-compat-binding` or first identity-export auto-issue; its absence after a key rotation means the required re-issue has not happened yet. |
| `ecosystem_export_generated` (INFO) | `jacs_compatibility_export_total{format}` | ecosystem export | Success, not a failure — six formats, exactly the six binding scopes: `jwks`, `did`, `a2a-agent-card`, `w3c-agent-identity`, `ap2-mandate`, `agreement-vc`. |

Metric label values are fixed, low-cardinality strings (`reason`,
`format`) — never raw error text.

Two boundary notes for dashboard authors:

- The `did` and `w3c-agent-identity` exports are **gate-and-enrich** views:
  without a valid binding granting the scope they still succeed in their
  pre-P2 native-only shape and emit **no** event or counter. Only the
  authorized (compat-enriched) exports appear under
  `jacs_compatibility_export_total`. One exception to the silence: when
  the compat key state exists but is unreadable (corrupt keyring,
  missing key file), the native-only fallback emits the
  `compatibility_key_unreadable` WARN above.
- Exporting the compatibility key binding itself (`jacs agent
  export-compat-binding`) is the trust artifact behind the six scoped
  exports, not one of them — it logs a plain INFO line and never appears
  under the `format` label.

## See Also

- [Creating and Using Agreements](../rust/agreements.md) - Agreement creation and signing workflow
- [Security Model](security.md) - Overall security architecture, including the compatibility key binding lifecycle
- [Key Rotation](key-rotation.md) - Rotation, Ed25519 migration, and binding re-issue
- [Cryptographic Algorithms](crypto.md) - Algorithm details and signature verification
