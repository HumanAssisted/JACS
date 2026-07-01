# P2 PQ-Root Targeted Export Smoke Checklist

This checklist matches the P2 plan after targeted ecosystem content exports were brought into scope.

The smoke goal is narrow:

1. a new JACS agent signs native JACS documents with `pq2025`
2. the agent has an ES256 compatibility key unless explicitly opted out
3. existing agents add the ES256 key only through explicit migration
4. the ES256 key is encrypted at rest with the existing JACS key envelope
5. a PQ-signed compatibility binding ties the ES256 public key and export scopes to the JACS agent id
6. JWKS, DID, W3C, and A2A exports can point back to that binding
7. AP2 mandate and Agreement-v2-as-VC exports are targeted ecosystem artifacts, not native JACS projections

## Task 001 - Native PQ Signing Policy

```bash
cargo test -p jacs-core --test sign_pq2025 -- --nocapture native
cargo test -p jacs-core --test schema -- --nocapture signing_algorithm
cargo test -p jacs-binding-core --test contract -- --nocapture algorithm
```

Expected:

- new native signatures use `pq2025`
- native ES256 is rejected at parse, schema, and verify layers
- `signingAlgorithm` is optional in schema for legacy compatibility but set to `pq2025` by new signatures
- an existing Ed25519-rooted agent still signs (grandfathered) and logs WARN `native_legacy_ed25519_sign`
- `rotate_keys` yields a `pq2025` root — by argument and by default — even for a grandfathered Ed25519 agent
- legacy verification still works

## Task 002 - Role-Based Keyring, Init, and Migration

```bash
cargo test -p jacs --test compatibility_keyring -- --nocapture
cargo test -p jacs-cli --test cli_compat_key -- --nocapture
```

Expected:

- fresh init/create produces `native_root:pq2025`
- fresh init/create produces `ecosystem_signing:ES256` unless `--no-compat-key` is used
- existing agent load generates no new keys
- `jacs agent add-compat-key` migrates an existing agent
- compatibility private key uses encrypted-at-rest storage and private filesystem permissions

## Task 003 - Compatibility Key Binding

```bash
cargo test -p jacs --test compatibility_key_binding -- --nocapture
cargo test -p jacs-core --test schema -- --nocapture compatibility_key_binding
```

Expected:

- binding validates against its schema
- binding has native `jacsSignature.signingAlgorithm == "pq2025"`
- binding can authorize identity scopes and content scopes
- swapping the ES256 key or tampering with the binding fails verification
- the latest-`issuedAt` binding wins; a binding signed by a previous (rotated-away) PQ root no longer authorizes exports
- an expired binding denies export

## Task 004 - Ecosystem Identity Exports

```bash
cargo test -p jacs --test ecosystem_identity_exports -- --nocapture
cargo test -p jacs --test a2a_keys_tests -- --nocapture es256
cargo test -p jacs --test w3c_fixtures -- --nocapture
```

Expected:

- JWKS exports the ES256 public key with a stable `kid`
- DID/W3C identity export lists the ES256 verification method
- A2A export uses the bound ES256 compatibility key when needed
- every identity export embeds or references the PQ-signed compatibility binding

## Task 004b - AP2 Mandate Export

```bash
cargo test -p jacs --test ap2_mandate_export -- --nocapture
```

Expected:

- typed AP2 mandate exports as detached ES256 JWS over JCS bytes
- exporter rejects non-mandate input
- known-answer vector matches the pinned AP2 spec/source used by the task
- export fails without `ap2-mandate` scope in the PQ-signed binding
- native source document still verifies unchanged after export
- stock JOSE verification accepts the ES256 JWS but does not assert PQ-root trust by itself

## Task 004c - Agreement-v2-as-VC Export

```bash
cargo test -p jacs --test agreement_v2_vc_export --features agreements -- --nocapture
cargo test -p jacs-binding-core --test agreement_v2_json -- --nocapture export_vc
# feature-gate guard: vc.rs must not leak into default features
RUSTFLAGS="-D warnings" cargo check -p jacs
RUSTFLAGS="-D warnings" cargo check -p jacs --features agreements
```

Expected:

- Agreement-v2 JSON exports as a schema-pinned VC
- VC uses `ecdsa-jcs-2019`
- exporter rejects non-agreement input
- independent Data Integrity vector verifies
- export fails without `agreement-vc` scope in the PQ-signed binding
- native agreement document still verifies unchanged after export

## Task 005 - Public Surface Parity

```bash
cargo test -p jacs-binding-core --test method_parity -- --nocapture
cargo test -p jacs-cli --test cli_command_snapshot -- --nocapture
cargo test -p jacs-binding-core --test cli_mcp_alignment -- --nocapture
cargo test -p jacs-mcp --test contract_snapshot -- --nocapture
```

Expected:

- export and migration methods exist consistently across bindings
- CLI and MCP contract fixtures match implementation
- AP2 and Agreement-VC content exporters are CLI-only in P2
- no generic ES256/JWS/Data Integrity/DSSE signing surface appears

## Task 006 - Legacy Verify and Scope Guardrails

```bash
cargo test -p jacs --test legacy_verify_guardrails -- --nocapture
cargo test -p jacs-binding-core --test contract -- --nocapture guardrail
```

Expected:

- legacy supported fixtures verify
- native verify rejects a document whose native `signingAlgorithm` is mutated to `ES256`
- new native ES256 signing remains unavailable
- native documents do not gain projection fields
- no public method accepts arbitrary document plus caller-selected algorithm or suite
- targeted content exports do not mutate native JACS documents

## Task 007 - Observability and Docs

```bash
cargo test -p jacs --test compatibility_observability -- --nocapture
cargo test -p jacs-cli --test mcp_observability_tests -- --nocapture compatibility
cargo test -p jacs-mcp --test tool_surface -- --nocapture compatibility
```

Expected:

- missing compatibility key logs WARN
- binding verification failure logs WARN
- content export without scope logs WARN
- grandfathered Ed25519 signing logs WARN `native_legacy_ed25519_sign`
- successful ecosystem export logs INFO with format, key id, and binding hash
- the §9.8 counters increment (`jacs_compatibility_export_total{format}` etc.) — asserted, not just documented
- docs explain CLI-only content exporters, the trust-chain degradation, and the no-generic-projection boundary

## End-to-End CLI Smoke (the deliverable surface, not just cargo tests)

The checks above are cargo tests; this section exercises the actual commands a user runs, plus the external verifiers that prove interoperability (NFR8).

```bash
# fresh agent: PQ root + ES256 compat key + binding
export JACS_PRIVATE_KEY_PASSWORD='smoke-password'
jacs init --name p2-smoke --domain example.com
jacs agent export-jwks > /tmp/p2_jwks.json
jacs agent export-compat-binding > /tmp/p2_binding.json

# migration path: an existing (pre-P2 / --no-compat-key) agent gains the key only explicitly
jacs agent add-compat-key

# content exports (CLI-only in P2; stdin form works like the rest of the agreement-v2 group)
jacs ap2 export-mandate --input ./fixtures/ap2_mandate_sample.json > /tmp/p2_mandate.jws
cat ./fixtures/agreement_v2_sample.json | jacs agreement-v2 export-vc --agreement - > /tmp/p2_agreement_vc.json

# external verification — stock tooling, no JACS installed
node scripts/smoke/verify_ap2_jws.mjs /tmp/p2_mandate.jws /tmp/p2_jwks.json   # stock `jose` verifier accepts the detached ES256 JWS
# independent Data Integrity check of the agreement VC (ecdsa-jcs-2019, Multikey verification method)
node scripts/smoke/verify_di_vc.mjs /tmp/p2_agreement_vc.json

# native wall — both must hold after every export
jacs verify signed-document.json          # native doc unchanged: same jacsSha256, pq2025 signature verifies
# a native doc with signingAlgorithm mutated to "ES256" must FAIL verification (covered by legacy_verify_guardrails)
```

Expected:

- every CLI command above exits 0 (except the mutated-algorithm negative, which must fail)
- the stock JOSE verifier accepts the AP2 mandate JWS; the independent DI verifier accepts the agreement VC
- exports without the matching binding scope fail with a typed error and a WARN `content_export_scope_denied`
- the native source documents verify unchanged after every export
