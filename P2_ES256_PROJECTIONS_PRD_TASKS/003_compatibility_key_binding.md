# Task 003 - Compatibility Key Binding Document

**Depends on:** 002  
**Unlocks:** 004, 007  
**Reversible:** one commit; remove schema and binding export helper

## Objective

Create a PQ-signed compatibility key binding document that binds the ES256 compatibility public key to the JACS agent id and PQ root.

This is the trust bridge between JACS and external ecosystems.

## TDD: Tests First (Red)

Add tests before implementation:

- `jacs/tests/compatibility_key_binding.rs`
  - `binding_is_signed_with_pq_root`
  - `binding_contains_es256_public_jwk_and_kid`
  - `binding_scope_must_include_requested_export`
  - `binding_fails_if_es256_key_is_swapped`
  - `binding_fails_if_jacs_signature_is_tampered`
- `jacs-core/tests/schema.rs`
  - `compatibility_key_binding_schema_accepts_valid_document`
  - `compatibility_key_binding_schema_rejects_missing_scope`
  - `compatibility_key_binding_schema_requires_pq_signature`

## Implementation Notes

Add a separate schema and helper module:

- `jacs-core/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json`
- `jacs/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json`
- `jacs/src/compatibility/binding.rs`
- `jacs/src/compatibility/mod.rs`

The binding document should include:

- `jacsDocumentType: "compatibilityKeyBinding"`
- JACS agent id
- root key algorithm and `kid`
- ES256 public JWK and `kid`
- scope array
- issued timestamp
- optional expiration
- native `jacsSignature` with `signingAlgorithm: "pq2025"`

Do not add protocol-specific compatibility fields to `jacs-core/schemas/agent/v1/agent.schema.json`.

## TDD: Tests Pass (Green)

Run:

```bash
cargo test -p jacs --test compatibility_key_binding -- --nocapture
cargo test -p jacs-core --test schema -- --nocapture compatibility_key_binding
```

Expected result:

- valid bindings validate and verify
- tampered bindings fail native JACS verification
- swapped ES256 keys fail binding checks

## Acceptance Criteria

- Binding is a separate schema/document type.
- Binding uses native PQ `jacsSignature`.
- Binding can be exported as canonical JSON.
- Binding verification checks key id, public key material, JACS agent id, and scope.

