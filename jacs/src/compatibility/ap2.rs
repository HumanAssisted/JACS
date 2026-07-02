//! AP2 merchant-authorization mandate export (P2 Task 004b, FR15).
//!
//! Produces the merchant/business-authorization artifact of the UCP
//! AP2-Mandates extension (spec revision [`AP2_SPEC_REVISION`]) as a
//! **detached** compact ES256 JWS. This is a purpose-built content
//! exporter, not a generic JWS API: input is validated against the named
//! mandate schema, the algorithm is fixed to ES256, the `ap2-mandate`
//! binding scope gates it (content scopes are NEVER auto-issued), and no
//! native JACS document is touched.
//!
//! Wire format, pinned:
//! - protected header exactly `{"alg":"ES256","kid":"<compat-key kid>"}`
//!   — no `typ`, no RFC 7797 `b64:false`, no `crit`
//! - detached compact serialization `<BASE64URL(header)>..<BASE64URL(sig)>`
//! - signing input `BASE64URL(header) + "." + BASE64URL(JCS(payload))`
//!   where the payload is the checkout object EXCLUDING the `ap2` field
//!
//! User-side AP2 Checkout Mandates are SD-JWT-VC and out of P2 scope;
//! this module never claims full AP2 conformance.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::error::JacsError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use std::sync::LazyLock;
use tracing::info;

/// Dated revision of the UCP AP2-Mandates extension the exporter targets.
pub const AP2_SPEC_REVISION: &str = "2026-01-23";

static AP2_MANDATE_SCHEMA: &str =
    include_str!("../../schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json");

static AP2_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema: Value =
        serde_json::from_str(AP2_MANDATE_SCHEMA).expect("embedded ap2-mandate schema parses");
    jsonschema::Validator::options()
        .with_draft(jsonschema::Draft::Draft7)
        .build(&schema)
        .expect("embedded ap2-mandate schema compiles")
});

/// Validate checkout input against the named mandate schema. A naming
/// convention is not a boundary — non-conforming input is rejected here.
fn validate_mandate_input(checkout: &Value) -> Result<(), JacsError> {
    let errors: Vec<String> = AP2_VALIDATOR
        .iter_errors(checkout)
        .map(|e| format!("{} (at {})", e, e.instance_path))
        .collect();
    if !errors.is_empty() {
        return Err(JacsError::ValidationError(format!(
            "input is not an AP2 mandate checkout (schema compatibility/ap2-mandate/v1): {}",
            errors.join("; ")
        )));
    }
    Ok(())
}

/// Build the detached ES256 JWS over the checkout (excluding `ap2`).
/// Returns `(detached_jws, payload_jcs)`. `pub(crate)` so the KAT unit
/// test can pin the exact bytes with a fixed key.
pub(crate) fn build_ap2_detached_jws(
    private_pkcs8_der: &[u8],
    kid: &str,
    checkout: &Value,
) -> Result<(String, String), JacsError> {
    let mut payload = checkout.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("ap2");
    }
    let payload_jcs = jacs_core::canonical::canonicalize_json_try(&payload)
        .map_err(|e| JacsError::ValidationError(format!("JCS canonicalization failed: {e}")))?;

    // Header pinned per FR15: exactly alg + kid.
    let header = json!({ "alg": "ES256", "kid": kid });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_jcs.as_bytes());

    // The classic detached-JWS bug is signing the raw JCS bytes; the
    // signing input is the standard compact form over the b64 payload.
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature =
        crate::crypt::es256::sign_es256_jose(private_pkcs8_der, signing_input.as_bytes())?;
    let detached = format!("{}..{}", header_b64, URL_SAFE_NO_PAD.encode(&signature));
    Ok((detached, payload_jcs))
}

/// Export the AP2 merchant-authorization mandate for `checkout_json`.
///
/// Requires the `ap2-mandate` binding scope — content exports never
/// auto-issue a binding; the PQ root must have granted the scope
/// explicitly. The result carries the detached JWS, the checkout with
/// `ap2.merchant_authorization` filled in, and the binding reference as
/// a content hash (never a URL).
pub fn export_ap2_mandate(
    agent: &mut Agent,
    key_directory: &str,
    checkout_json: &str,
) -> Result<Value, JacsError> {
    let checkout: Value = serde_json::from_str(checkout_json).map_err(|e| {
        super::record_export_error("ap2-mandate", "invalid_input");
        JacsError::ValidationError(format!("mandate input is not JSON: {e}"))
    })?;
    if !checkout.is_object() {
        super::record_export_error("ap2-mandate", "invalid_input");
        return Err(JacsError::ValidationError(
            "mandate input must be a checkout JSON object".to_string(),
        ));
    }
    validate_mandate_input(&checkout)
        .inspect_err(|_| super::record_export_error("ap2-mandate", "invalid_input"))?;

    // Content scope: require_scope directly — no auto-issue path.
    let binding = super::binding::require_scope(agent, key_directory, "ap2-mandate")?;
    let binding_hash = super::binding::binding_hash(&binding);
    // Missing keys fail (and count as `missing_key`) inside `require_scope`.
    let compat = crate::keystore::compat::ecosystem_key_info(key_directory)?;

    // Decrypt the ES256 private key; plaintext PKCS#8 DER lives only in
    // the returned zeroizing buffer for the duration of the signing call.
    let private_der = super::decrypt_ecosystem_private_key(agent, &compat)?;
    let (detached_jws, _payload_jcs) =
        build_ap2_detached_jws(private_der.as_slice(), &compat.kid, &checkout)?;

    let mut signed_checkout = checkout;
    let ap2_block = signed_checkout
        .as_object_mut()
        .expect("checked is_object above")
        .entry("ap2")
        .or_insert_with(|| json!({}));
    if !ap2_block.is_object() {
        return Err(JacsError::ValidationError(
            "checkout `ap2` field must be an object".to_string(),
        ));
    }
    ap2_block["merchant_authorization"] = json!(detached_jws);

    info!(
        event = "ecosystem_export_generated",
        format = "ap2-mandate",
        jacs_id = %agent.get_id().unwrap_or_default(),
        kid = %compat.kid,
        binding_hash = %binding_hash,
        spec_revision = AP2_SPEC_REVISION,
        "AP2 merchant-authorization mandate exported as detached ES256 JWS"
    );
    super::record_export_generated("ap2-mandate");

    Ok(json!({
        "format": "ap2-mandate",
        "role": "merchant-authorization",
        "specRevision": AP2_SPEC_REVISION,
        "kid": compat.kid,
        "jacsCompatBindingHash": binding_hash,
        "detachedJws": detached_jws,
        "checkout": signed_checkout
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed KAT keypair (test-only, generated for this vector; never a
    /// real agent key). kid is the RFC 7638 thumbprint of the public JWK.
    const KAT_PRIVATE_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH0f63vJ/+mvwadvg2Lqva2GHVQblDAP9EIkioLBYMIahRANCAATl9hSIv3VesCf2Wps3DEZTZjrIms+zVlsha4QSG3bwdaBnN+qpIwQRvb2NfO+q5IrOx+BwwDPNJAfUtiZLgBAk";
    const KAT_KID: &str = "Xwsjg5-yeDmbHuqkyQC2OqAzJdmA7lrt9B67Pe9-Ak0";

    const KAT_CHECKOUT: &str = r#"{
        "id": "checkout_kat_001",
        "status": "ready_for_payment",
        "currency": "USD",
        "line_items": [
            {
                "id": "li_1",
                "title": "JACS Pro License",
                "quantity": 1,
                "base_amount": 5000,
                "total_amount": 5000
            }
        ],
        "totals": [
            { "type": "subtotal", "display_text": "Subtotal", "amount": 5000 },
            { "type": "total", "display_text": "Total", "amount": 5000 }
        ],
        "ap2": { "risk_signals": { "session_age_seconds": 42 } }
    }"#;

    /// JCS of the checkout EXCLUDING `ap2`: keys sorted, no whitespace.
    const KAT_EXPECTED_PAYLOAD_JCS: &str = r#"{"currency":"USD","id":"checkout_kat_001","line_items":[{"base_amount":5000,"id":"li_1","quantity":1,"title":"JACS Pro License","total_amount":5000}],"status":"ready_for_payment","totals":[{"amount":5000,"display_text":"Subtotal","type":"subtotal"},{"amount":5000,"display_text":"Total","type":"total"}]}"#;

    /// Pinned known-answer detached JWS. RustCrypto p256 signs per
    /// RFC 6979 (deterministic), so this vector is byte-exact across
    /// builds. It pins the header serialization, the JCS payload, AND the
    /// signing input `header_b64 . payload_b64` — the classic detached
    /// bug (signing raw JCS bytes) produces a different signature and
    /// fails here.
    /// Independently verified with stock JOSE tooling (the `jose` npm
    /// package plus the `canonicalize` RFC 8785 implementation) — see
    /// `scripts/smoke/verify_ap2_jws.mjs`.
    const KAT_EXPECTED_DETACHED_JWS: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6Ilh3c2pnNS15ZURtYkh1cWt5UUMyT3FBekpkbUE3bHJ0OUI2N1BlOS1BazAifQ..27x8jJQ09apzFiH6mJUf0DJCR9C3tl0W57AVhjM2jmYm7xUw7H0zX8i73_ftGMfRqxdprrUIKYtrTaEpZsWPZA";

    #[test]
    fn ap2_detached_jws_matches_known_answer_vector() {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(KAT_PRIVATE_PKCS8_B64)
            .expect("KAT key decodes");
        let checkout: Value = serde_json::from_str(KAT_CHECKOUT).expect("KAT checkout parses");

        let (detached, payload_jcs) =
            build_ap2_detached_jws(&der, KAT_KID, &checkout).expect("build detached JWS");

        assert_eq!(payload_jcs, KAT_EXPECTED_PAYLOAD_JCS, "JCS payload drift");
        assert_eq!(detached, KAT_EXPECTED_DETACHED_JWS, "detached JWS drift");

        // Shape: exactly <header>..<sig>, empty payload segment.
        let parts: Vec<&str> = detached.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[1].is_empty(), "payload segment must be detached");

        // Header decodes to exactly {"alg","kid"} — no typ/b64/crit.
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("header b64"))
                .expect("header json");
        let obj = header.as_object().unwrap();
        assert_eq!(obj.len(), 2, "header has exactly alg and kid: {header}");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], KAT_KID);
    }
}
