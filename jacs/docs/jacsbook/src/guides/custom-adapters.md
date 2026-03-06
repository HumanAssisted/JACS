# Writing a Custom Evidence Adapter

Evidence adapters normalize external proof sources into JACS attestation claims and
evidence references. JACS ships with A2A and Email adapters; you can add your own
for JWT tokens, TLSNotary proofs, or any custom evidence source.

## What Is an EvidenceAdapter?

An `EvidenceAdapter` is a Rust trait with three methods:

```rust
pub trait EvidenceAdapter: Send + Sync + std::fmt::Debug {
    /// Returns the kind string (e.g., "jwt", "tlsnotary", "custom").
    fn kind(&self) -> &str;

    /// Normalize raw evidence bytes + metadata into claims + evidence reference.
    fn normalize(
        &self,
        raw: &[u8],
        metadata: &serde_json::Value,
    ) -> Result<(Vec<Claim>, EvidenceRef), Box<dyn Error>>;

    /// Verify a previously created evidence reference.
    fn verify_evidence(
        &self,
        evidence: &EvidenceRef,
    ) -> Result<EvidenceVerificationResult, Box<dyn Error>>;
}
```

The adapter lifecycle:

1. **At attestation creation time:** `normalize()` is called with raw evidence bytes
   and optional metadata. It returns structured claims and an `EvidenceRef` that will
   be embedded in the attestation document.
2. **At verification time (full tier):** `verify_evidence()` is called with the stored
   `EvidenceRef` to re-validate the evidence.

## The normalize() Contract

`normalize()` must:

- Compute content-addressable digests of the raw evidence using `compute_digest_set_bytes()`
- Decide whether to embed the evidence (recommended for data under 64KB)
- Extract meaningful claims from the evidence
- Set appropriate `confidence` and `assuranceLevel` values
- Include a `collectedAt` timestamp
- Return a `VerifierInfo` identifying your adapter and version

`normalize()` must NOT:

- Make network calls (normalization should be deterministic and fast)
- Modify the raw evidence
- Set confidence to 1.0 unless the evidence is self-verifying (e.g., a valid cryptographic proof)

## The verify_evidence() Contract

`verify_evidence()` must:

- Verify the digest integrity (re-hash and compare)
- Check freshness (is the `collectedAt` timestamp within acceptable bounds?)
- Return a detailed `EvidenceVerificationResult` with `digest_valid`, `freshness_valid`, and human-readable `detail`

`verify_evidence()` may:

- Make network calls (for remote evidence resolution)
- Access the file system (for local evidence files)
- Return partial results (e.g., digest valid but freshness expired)

## Step-by-Step: Building a JWT Adapter

Here is a complete example of a JWT evidence adapter:

```rust
use crate::attestation::adapters::EvidenceAdapter;
use crate::attestation::digest::compute_digest_set_bytes;
use crate::attestation::types::*;
use serde_json::Value;
use std::error::Error;

#[derive(Debug)]
pub struct JwtAdapter;

impl EvidenceAdapter for JwtAdapter {
    fn kind(&self) -> &str {
        "jwt"
    }

    fn normalize(
        &self,
        raw: &[u8],
        metadata: &Value,
    ) -> Result<(Vec<Claim>, EvidenceRef), Box<dyn Error>> {
        // 1. Parse the JWT (header.payload.signature)
        let jwt_str = std::str::from_utf8(raw)?;
        let parts: Vec<&str> = jwt_str.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT: expected 3 dot-separated parts".into());
        }

        // 2. Decode the payload (base64url)
        let payload_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1],
        )?;
        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        // 3. Compute content-addressable digests
        let digests = compute_digest_set_bytes(raw);

        // 4. Extract claims (only non-PII fields per TRD Decision 14)
        let mut claims = vec![];
        if let Some(iss) = payload.get("iss") {
            claims.push(Claim {
                name: "jwt-issuer".into(),
                value: iss.clone(),
                confidence: Some(0.8),
                assurance_level: Some(AssuranceLevel::Verified),
                issuer: iss.as_str().map(String::from),
                issued_at: Some(crate::time_utils::now_rfc3339()),
            });
        }
        if let Some(sub) = payload.get("sub") {
            claims.push(Claim {
                name: "jwt-subject".into(),
                value: sub.clone(),
                confidence: Some(0.8),
                assurance_level: Some(AssuranceLevel::Verified),
                issuer: None,
                issued_at: None,
            });
        }

        // 5. Build the evidence reference
        let evidence = EvidenceRef {
            kind: EvidenceKind::Jwt,
            digests,
            uri: metadata.get("uri").and_then(|v| v.as_str()).map(String::from),
            embedded: raw.len() < 65536,
            embedded_data: if raw.len() < 65536 {
                Some(Value::String(jwt_str.to_string()))
            } else {
                None
            },
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Restricted, // JWTs may contain PII
            verifier: VerifierInfo {
                name: "jacs-jwt-adapter".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        };

        Ok((claims, evidence))
    }

    fn verify_evidence(
        &self,
        evidence: &EvidenceRef,
    ) -> Result<EvidenceVerificationResult, Box<dyn Error>> {
        // Re-verify the digest
        let digest_valid = if let Some(ref data) = evidence.embedded_data {
            let raw = data.as_str().unwrap_or("").as_bytes();
            let recomputed = compute_digest_set_bytes(raw);
            recomputed.sha256 == evidence.digests.sha256
        } else {
            // Cannot verify without embedded data or fetchable URI
            false
        };

        // Check freshness (example: 5 minute max age)
        let freshness_valid = true; // Implement actual time check

        Ok(EvidenceVerificationResult {
            kind: "jwt".into(),
            digest_valid,
            freshness_valid,
            detail: if digest_valid {
                "JWT digest verified".into()
            } else {
                "JWT digest mismatch or data unavailable".into()
            },
        })
    }
}
```

## Testing Your Adapter

Write tests that cover:

1. **Normal case:** Valid evidence normalizes to expected claims
2. **Invalid input:** Malformed evidence returns a clear error
3. **Digest verification:** Round-trip through normalize + verify_evidence
4. **Empty evidence:** Edge case handling

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jwt_normalize_extracts_issuer() {
        let adapter = JwtAdapter;
        // Build a minimal JWT (header.payload.signature)
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"alg\":\"RS256\"}",
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            b"{\"iss\":\"auth.example.com\",\"sub\":\"user-123\"}",
        );
        let jwt = format!("{}.{}.fake-sig", header, payload);

        let (claims, evidence) = adapter
            .normalize(jwt.as_bytes(), &json!({}))
            .expect("normalize should succeed");

        assert!(claims.iter().any(|c| c.name == "jwt-issuer"));
        assert_eq!(evidence.kind, EvidenceKind::Jwt);
    }
}
```

## Registering Your Adapter with the Agent

Adapters are registered on the `Agent` struct via the evidence adapter list. To add
your adapter to the default set, modify `adapters/mod.rs`:

```rust
pub fn default_adapters() -> Vec<Box<dyn EvidenceAdapter>> {
    vec![
        Box::new(a2a::A2aAdapter),
        Box::new(email::EmailAdapter),
        Box::new(jwt::JwtAdapter),  // Add your adapter here
    ]
}
```

For runtime registration (without modifying JACS source), use the agent's adapter
API (when available in a future release).

## Privacy Considerations

The `EvidenceSensitivity` enum controls how evidence is handled:

- **Public:** Evidence can be freely shared and embedded
- **Restricted:** Evidence should be handled with care; consider redacting PII
- **Confidential:** Evidence should not be embedded; use content-addressable URI references only

For JWTs and other credential-based evidence, default to `Restricted` and only
include non-PII fields (`iss`, `sub`, `aud`, `iat`, `exp`) in claims.
