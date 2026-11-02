# Writing a Custom Evidence Adapter

Evidence adapters normalize external bytes into claims and evidence references.
They belong to the retained native Rust `jacs` crate with the `attestation`
feature enabled.

The built-in A2A and Email adapters are **digest-only**: they do not verify
A2A/JACS signatures, DKIM, S/MIME, PGP, sender identity or signer trust. Their
claims use `self-asserted` assurance and names ending in
`evidence-digest-recorded`. Use the corresponding protocol verifier before
asserting protocol or identity verification.

## Trait contract

External implementations import the public types from `jacs`:

```rust
use jacs::attestation::adapters::EvidenceAdapter;
use jacs::attestation::types::{Claim, EvidenceRef, EvidenceVerificationResult};
use jacs::error::JacsError;
use serde_json::Value;
```

The required method signatures are:

```text
fn kind(&self) -> &str;
fn normalize(&self, raw: &[u8], metadata: &Value)
    -> Result<(Vec<Claim>, EvidenceRef), JacsError>;
fn verify_evidence(&self, evidence: &EvidenceRef)
    -> Result<EvidenceVerificationResult, JacsError>;
```

An implementation must also implement `Send + Sync + Debug`.
See the [trait and built-in implementations](https://github.com/HumanAssisted/JACS/tree/main/archive/native/jacs/src/attestation/adapters)
for complete types and executable examples.

## Normalize and register explicitly

Call your adapter's `normalize()` on the raw bytes and metadata, then supply
the returned claims and evidence to attestation creation. The raw creation API
takes already-normalized values; it does not automatically call every adapter.

Register a custom adapter on a mutable native `Agent` with
`agent.register_adapter(Box::new(adapter))`. This API exists now. Registration
makes matching evidence kinds available during full attestation verification;
it does not require editing JACS's default adapter list.

## Preserve the evidence's meaning

Compute digests over an explicitly defined byte representation and preserve that
representation for later verification. Reformatting JSON, decoding strings or
redacting fields can change the bytes. Keep parsing separate from authentication:
decoding a JWT payload does not verify its signature, issuer, audience or expiry.

`normalize()` receives untrusted data and metadata. Do not promote a caller's
`verified=true` or a successful digest computation into verified assurance.
A confidence value is an assertion, not proof. State exactly which protocol
checks your implementation performs and which trust policy supplies its keys.

`verify_evidence()` returns `digest_valid`, `freshness_valid` and a
human-readable `detail` in Rust. Implement actual checks before reporting
success. If required bytes, trust anchors or time context are unavailable, return
a failure or an explicit error rather than a fabricated passing result. The
built-in full verifier does not fetch URI-only evidence.

## Privacy and testing

Sensitivity labels do not encrypt evidence or grant access control. JWT subject,
issuer and audience fields may identify people or organizations; minimize them
and avoid embedding bearer tokens or other credentials. Select URI resolution,
retention and access policy in the application.

Test malformed input, digest mutations, unavailable evidence, expired or
future-dated evidence, untrusted keys, incorrect issuer/audience, and round trips
that preserve exact bytes. Include assertions that an unauthenticated source
never produces a claim of verified identity.

See [attestation creation and verification](attestation-tutorial.md) and
[testing](../advanced/testing.md).
