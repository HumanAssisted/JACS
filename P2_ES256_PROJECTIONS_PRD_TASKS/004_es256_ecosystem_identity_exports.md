# Task 004 - ES256 Ecosystem Identity Exports

**Depends on:** 003  
**Unlocks:** 005, 007  
**Reversible:** one commit; remove compatibility export helpers

## Objective

Export standard ecosystem identity documents using the ES256 compatibility key, and include or reference the PQ-signed compatibility key binding.

This task is about identity exports, not generic document projections.

## TDD: Tests First (Red)

Add tests before implementation:

- `jacs/tests/ecosystem_identity_exports.rs`
  - `jwks_exports_es256_public_key_with_stable_kid`
  - `jwks_does_not_publish_pq_private_or_native_signing_material`
  - `did_document_lists_es256_verification_method`
  - `did_document_references_or_embeds_pq_binding`
  - `a2a_agent_card_uses_bound_es256_key_when_required`
  - `export_fails_when_binding_scope_missing`
  - `export_does_not_add_jacs_projections_to_native_document`
- `jacs/tests/a2a_keys_tests.rs`
  - replace ES256 stub expectations with real compatibility-key export behavior
- `jacs/tests/w3c_fixtures.rs`
  - update W3C fixture expectations for the ES256 compatibility method

Add a documented external smoke vector if practical, but do not add a heavyweight JOSE dependency to CI unless required.

## Implementation Notes

Likely touch:

- `jacs/src/compatibility/es256.rs`
  - ES256 key generation/signing/JWK export helpers
  - RFC 7638 `kid` generation for public JWK
- `jacs/src/a2a/keys.rs`
  - remove "ES256 not implemented" stubs by delegating to compatibility helpers
  - keep behavior limited to A2A/identity export needs
- `jacs/src/a2a/agent_card.rs`
  - include binding reference or binding extension in exported card
- `jacs/src/w3c/did_wba.rs`
  - emit ES256 verification method for compatibility identity
- `jacs/src/w3c/agent_description.rs`
  - include compatibility metadata where the W3C format supports it

Dependency posture:

- use a narrow RustCrypto ES256 implementation if a new dependency is needed
- do not use `ring` in portable paths
- do not add broad JOSE frameworks for a small JWK/signing surface

## TDD: Tests Pass (Green)

Run:

```bash
cargo test -p jacs --test ecosystem_identity_exports -- --nocapture
cargo test -p jacs --test a2a_keys_tests -- --nocapture es256
cargo test -p jacs --test w3c_fixtures -- --nocapture
```

Expected result:

- JWKS, DID, W3C, and A2A exports identify the same ES256 compatibility key
- every export can be traced to a PQ-signed binding
- no native JACS document gains a projection field

## Acceptance Criteria

- ES256 is implemented only for ecosystem compatibility exports.
- JWKS `kid` is stable for the same ES256 public key.
- A2A export chooses either embedded binding or binding reference according to the simplest format-compatible path.
- The native agent schema remains protocol-neutral.

