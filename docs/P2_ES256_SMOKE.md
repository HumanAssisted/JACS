# P2 PQ-Root Compatibility Smoke Checklist

This checklist replaces the old ES256 projection smoke plan. P2 no longer makes ES256 a native JACS signing algorithm and no longer adds generic document projections.

The smoke goal is narrower:

1. a new JACS agent signs native JACS documents with `pq2025`
2. the agent has an ES256 compatibility key
3. the ES256 key is encrypted at rest with the existing JACS key envelope
4. a PQ-signed compatibility binding ties the ES256 public key to the JACS agent id
5. JWKS, DID, W3C, and A2A exports can point back to that binding

## Task 001 - Native PQ Signing Policy

```bash
cargo test -p jacs-core --test sign_pq2025 -- --nocapture native
cargo test -p jacs-binding-core --test contract -- --nocapture algorithm
```

Expected:

- new native signatures use `pq2025`
- native ES256 is rejected
- legacy verification still works

## Task 002 - Role-Based Keyring and Init

```bash
cargo test -p jacs --test compatibility_keyring -- --nocapture
```

Expected:

- fresh init/create produces `native_root:pq2025`
- fresh init/create produces `ecosystem_signing:ES256`
- both private keys use encrypted-at-rest storage and private filesystem permissions

## Task 003 - Compatibility Key Binding

```bash
cargo test -p jacs --test compatibility_key_binding -- --nocapture
cargo test -p jacs-core --test schema -- --nocapture compatibility_key_binding
```

Expected:

- binding validates against its schema
- binding has native `jacsSignature.signingAlgorithm == "pq2025"`
- swapping the ES256 key or tampering with the binding fails verification

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
- every export embeds or references the PQ-signed compatibility binding

## Task 005 - Public Surface Parity

```bash
cargo test -p jacs-binding-core --test method_parity -- --nocapture
cargo test -p jacs-cli --test cli_command_snapshot -- --nocapture
cargo test -p jacs-binding-core --test cli_mcp_alignment -- --nocapture
cargo test -p jacs-mcp --test contract_snapshot -- --nocapture
```

Expected:

- export methods exist consistently across bindings
- CLI and MCP contract fixtures match implementation
- no generic ES256/JWS/Data Integrity/DSSE signing surface appears

## Task 006 - Legacy Verify and Scope Guardrails

```bash
cargo test -p jacs --test legacy_verify_guardrails -- --nocapture
```

Expected:

- legacy supported fixtures verify
- new native ES256 signing remains unavailable
- native documents do not gain projection fields

## Task 007 - Observability and Docs

```bash
cargo test -p jacs --test compatibility_observability -- --nocapture
cargo test -p jacs-cli --test mcp_observability_tests -- --nocapture compatibility
cargo test -p jacs-mcp --test tool_surface -- --nocapture compatibility
```

Expected:

- missing compatibility key logs WARN
- binding verification failure logs WARN
- successful ecosystem export logs INFO with format, key id, and binding hash
