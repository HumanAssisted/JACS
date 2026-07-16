# P2 Native-Root Targeted Export Smoke Checklist

This checklist matches the P2 plan after targeted ecosystem content exports were brought into scope.

The smoke goal is narrow:

1. a default new JACS agent signs native JACS documents with `pq2025`, while explicit Ed25519 selection remains truthful
2. the agent has an ES256 compatibility key unless explicitly opted out
3. existing agents add the ES256 key only through explicit migration
4. the ES256 key is encrypted at rest with the existing JACS key envelope
5. a native-root-signed compatibility binding ties the ES256 public key and export scopes to the JACS agent id
6. JWKS, DID, W3C, and A2A exports can point back to that binding
7. AP2 mandate and Agreement-v2-as-VC exports are targeted ecosystem artifacts, not native JACS projections

## Task 001 - Native PQ Signing Policy

```bash
cargo test -p jacs-core --test sign_pq2025 -- --nocapture native
cargo test -p jacs-core --test schema -- --nocapture signing_algorithm
cargo test -p jacs-binding-core --test contract -- --nocapture algorithm
```

Expected:

- default native signatures use `pq2025`; explicit `ed25519` uses `ring-Ed25519`
- native ES256 is rejected at parse, schema, and verify layers
- `signingAlgorithm` is optional in schema for legacy compatibility but set to `pq2025` by new signatures
- an Ed25519-rooted agent signs normally without a false legacy/rejection WARN
- `rotate_keys` yields a `pq2025` root — by argument and by default — even for an Ed25519 agent
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
- the latest-`issuedAt` binding wins; a binding signed by a previous (rotated-away) native root no longer authorizes exports
- an expired binding denies export

## Task 004 - Ecosystem Identity Exports

```bash
# a2a feature required: a2a_keys_tests is #![cfg(feature = "a2a")] (0 tests without it),
# and ecosystem_identity_exports gates its A2A cases on the same feature
cargo test -p jacs --features a2a --test ecosystem_identity_exports -- --nocapture
cargo test -p jacs --features a2a --test a2a_keys_tests -- --nocapture es256
cargo test -p jacs --test w3c_fixtures -- --nocapture
```

Expected:

- JWKS exports the ES256 public key with a stable `kid`
- DID/W3C identity export lists the ES256 verification method
- A2A export uses the bound ES256 compatibility key when needed
- every identity export embeds or references the native-root-signed compatibility binding

## Task 004b - AP2 Mandate Export

```bash
cargo test -p jacs --test ap2_mandate_export -- --nocapture
cargo test -p jacs --lib compatibility::ap2 -- --nocapture   # byte-exact KAT (fixed key)
cargo test -p jacs-cli --test cli_ap2_mandate -- --nocapture
```

Expected:

- typed AP2 mandate exports as detached ES256 JWS over JCS bytes
- exporter rejects non-mandate input
- known-answer vector matches the pinned AP2 spec/source used by the task
- export fails without `ap2-mandate` scope in the native-root-signed binding
- native source document still verifies unchanged after export
- stock JOSE verification accepts the ES256 JWS but does not assert native-root trust by itself

## Task 004c - Agreement-v2-as-VC Export

```bash
cargo test -p jacs --test agreement_v2_vc_export --features agreements -- --nocapture
cargo test -p jacs --features agreements --lib compatibility::vc -- --nocapture   # byte-exact W3C vc-di-ecdsa vector KAT
cargo test -p jacs-binding-core --features agreements --test agreement_v2_json -- --nocapture export_vc
cargo test -p jacs-cli --test cli_agreement_v2 -- --nocapture export_vc
# feature-gate guard: vc.rs must not leak into default features
RUSTFLAGS="-D warnings" cargo check -p jacs
RUSTFLAGS="-D warnings" cargo check -p jacs --features agreements
```

Expected:

- Agreement-v2 JSON exports as a schema-pinned VC
- VC uses `ecdsa-jcs-2019`
- exporter rejects non-agreement input
- independent Data Integrity vector verifies
- export fails without `agreement-vc` scope in the native-root-signed binding
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
# agreements feature required: the content-export no-mutation guardrails
# (agreement snapshot tests) are #[cfg(feature = "agreements")]
cargo test -p jacs --features agreements --test legacy_verify_guardrails -- --nocapture
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
# otlp-metrics gates the §9.8 counter assertions and agreements gates the
# agreement-vc events — same feature set as `make test-jacs-observability`
cargo test -p jacs --features "otlp-logs otlp-metrics otlp-tracing agreements" --test compatibility_observability -- --nocapture
cargo test -p jacs-cli --test mcp_observability_tests -- --nocapture compatibility
cargo test -p jacs-mcp --test tool_surface -- --nocapture compatibility
```

Expected:

- missing compatibility key logs WARN
- binding verification failure logs WARN
- content export without scope logs WARN
- supported Ed25519 signing emits the normal successful-signing signal
- successful ecosystem export logs INFO with format, key id, and binding hash
- the §9.8 counters increment (`jacs_compatibility_export_total{format}` etc.) — asserted, not just documented
- docs explain CLI-only content exporters, the trust-chain degradation, and the no-generic-projection boundary

### Docs checks

```bash
# 1. Negative: user docs must NOT present these as public native features
#    (mentions as negative guardrails or test names are fine — use judgment)
rg "ring-ES256|jacsProjections|sign-jws|sign-data-integrity|export-dsse-document|issue-w3c-vc" \
  README.md jacs/docs/jacsbook/src jacs-cli/README.md jacs-mcp/README.md

# 2. Positive: the P2 model must be findable in user docs
rg -l "native root|compatibility key binding|ES256 compatibility|AP2 mandate|Agreement-v2-as-VC" \
  README.md jacs/docs/jacsbook/src jacs-cli/README.md jacs-mcp/README.md
```

Expected:

- check 1 returns no hits that present these names as public native features
- check 2 lists the top-level README and jacsbook user docs (security, crypto, failure-modes, ap2, agreement-v2, cli-commands at minimum)

## End-to-End CLI Smoke (the deliverable surface, not just cargo tests)

The checks above are cargo tests; this section exercises the actual commands a user runs, plus the external verifiers that prove interoperability (NFR8).

`make smoke-verifiers` runs this whole section unattended (builds the CLI, creates a scratch agent, runs both content exports and both stock verifier scripts in a temp directory); CI runs it on every PR as the `smoke-verifiers` job in `.github/workflows/rust.yml`, so a bit-rotted verifier script fails the build. The manual transcript below is the same flow.

The verifier scripts resolve their npm dependencies (`jose`, `canonicalize`) from a `node_modules` next to (or above) the script file, so copy them into the scratch directory and install there.

```bash
JACS_REPO=$(pwd)                          # run this line from the repo root
WORK=$(mktemp -d) && cd "$WORK"

# fresh agent: native root (pq2025 by default) + ES256 compat key (quickstart is the non-interactive
# init path; `jacs init` prompts and is not scriptable)
export JACS_PRIVATE_KEY_PASSWORD='P2-Smoke-Password!2026'
jacs quickstart --name p2-smoke --domain example.com

# identity exports; the FIRST identity export auto-issues the default
# identity-scopes binding (content scopes are never part of it)
jacs agent export-jwks > p2_jwks.json
jacs agent export-compat-binding > p2_binding.json

# migration is EXPLICIT and one-shot: this fresh agent already has the key,
# so the command must FAIL with the typed duplicate error. (On a real
# pre-P2 / --no-compat-key agent, this same command performs the migration.)
jacs agent add-compat-key && echo "UNEXPECTED: duplicate add-compat-key succeeded" && exit 1
echo "ok: duplicate add-compat-key rejected"

# content scopes are NEVER auto-issued: grant them explicitly (native root signs)
jacs agent issue-compat-binding --scopes jwks,did,a2a-agent-card,w3c-agent-identity,ap2-mandate,agreement-vc

# content exports (CLI-only in P2; stdin form works like the rest of the agreement-v2 group)
cat > p2_checkout.json <<'EOF'
{
  "id": "checkout_smoke_001",
  "status": "ready_for_payment",
  "currency": "USD",
  "line_items": [
    { "id": "li_1", "title": "Widget", "quantity": 1, "base_amount": 990, "total_amount": 990 }
  ],
  "totals": [
    { "type": "total", "display_text": "Total", "amount": 990 }
  ]
}
EOF
jacs ap2 export-mandate --input p2_checkout.json > p2_mandate_export.json

AGENT_ID=$(python3 -c "import json; print(json.load(open('jacs.config.json'))['jacs_agent_id_and_version'].split(':')[0])")
cat > p2_agreement_input.json <<EOF
{
  "title": "P2 smoke agreement",
  "description": "Agreement used by the P2 smoke checklist.",
  "terms": "Party agrees to smoke-test things.",
  "termsFormat": "text/plain",
  "status": "proposed",
  "parties": [ { "agentId": "$AGENT_ID", "agentType": "ai", "role": "signer" } ],
  "signaturePolicy": { "partyQuorum": "all" },
  "controllers": [ "$AGENT_ID" ]
}
EOF
jacs agreement-v2 create --input p2_agreement_input.json > p2_agreement.json
cat p2_agreement.json | jacs agreement-v2 export-vc --agreement - > p2_agreement_vc.json

# external verification — stock tooling, no JACS verification code involved
cp "$JACS_REPO"/scripts/smoke/verify_ap2_jws.mjs "$JACS_REPO"/scripts/smoke/verify_di_vc.mjs .
npm install jose canonicalize
node verify_ap2_jws.mjs p2_mandate_export.json p2_jwks.json   # stock `jose` verifier accepts the detached ES256 JWS
# independent Data Integrity check of the agreement VC (ecdsa-jcs-2019, Multikey verification method)
node verify_di_vc.mjs p2_agreement_vc.json p2_jwks.json

# native wall — both must hold after every export
echo '{"claim":"native wall"}' | jacs quickstart --name p2-smoke --domain example.com --sign > p2_signed_document.json
jacs verify p2_signed_document.json       # native doc unchanged: pq2025 signature verifies
# a native doc with signingAlgorithm mutated to "ES256" must FAIL verification (covered by legacy_verify_guardrails)
```

Expected:

- every CLI command above exits 0 (except the mutated-algorithm negative, which must fail)
- the stock JOSE verifier accepts the AP2 mandate JWS; the independent DI verifier accepts the agreement VC
- exports without the matching binding scope fail with a typed error and a WARN `content_export_scope_denied`
- the native source documents verify unchanged after every export
