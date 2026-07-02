#![cfg(feature = "a2a")]
use jacs::a2a::keys::create_jwk_keys;

#[test]
fn test_create_dual_keys_ed25519() {
    let keys = create_jwk_keys(Some("ring-Ed25519"), Some("ring-Ed25519"))
        .expect("Ed25519 dual-key generation should succeed");
    assert_eq!(keys.jacs_algorithm, "ring-Ed25519");
    assert_eq!(keys.a2a_algorithm, "ring-Ed25519");
    assert_eq!(keys.jacs_public_key.len(), 32);
    assert_eq!(keys.a2a_public_key.len(), 32);
}

// ---------------------------------------------------------------------------
// P2 Task 006 — guardrails on the public jacs::a2a::keys surface (the API
// haisdk consumes). The Task 004/004b stub carve-out delegates ES256 KEY
// GENERATION and JWK EXPORT to real code, but the ES256 arms of sign_jws /
// verify_jws must keep returning errors (FR25 — no generic
// caller-chosen-algorithm ES256 signing surface).
// ---------------------------------------------------------------------------

/// The ES256 arms of the public `sign_jws` AND `verify_jws` still return
/// errors after Tasks 004/004b — even when handed a REAL ES256 private key
/// produced by the sanctioned keygen carve-out.
#[test]
fn a2a_sign_jws_still_rejects_es256() {
    use jacs::a2a::keys::{sign_jws, verify_jws};

    // Baseline: the Ed25519 path works, so the rejections below cannot be
    // blamed on a broken JWS pipeline.
    let ed_keys = create_jwk_keys(Some("ring-Ed25519"), Some("ring-Ed25519"))
        .expect("Ed25519 dual-key generation");
    let payload = b"guardrails payload";
    let jws = sign_jws(payload, &ed_keys.a2a_private_key, "ring-Ed25519", "kid-ed")
        .expect("Ed25519 JWS signing works");
    let roundtrip =
        verify_jws(&jws, &ed_keys.a2a_public_key, "ring-Ed25519").expect("Ed25519 JWS verifies");
    assert_eq!(roundtrip, payload);

    // Keygen carve-out still works — and hands us a genuine ES256 key.
    let es_keys = create_jwk_keys(None, Some("es256")).expect("ES256 A2A keygen carve-out");
    assert_eq!(es_keys.a2a_algorithm, "es256");

    // sign_jws: both spelled arms error, plus the unknown-alias fallthrough.
    for alg in ["es256", "ecdsa"] {
        let err = sign_jws(payload, &es_keys.a2a_private_key, alg, "kid-es")
            .expect_err("ES256 JWS signing must stay unavailable");
        assert!(
            err.to_string()
                .contains("ES256 JWS signing is not available through this generic API"),
            "sign_jws('{alg}') names the ES256 wall: {err}"
        );
    }
    let err = sign_jws(payload, &es_keys.a2a_private_key, "ES256", "kid-es")
        .expect_err("unknown 'ES256' spelling must also fail");
    assert!(
        err.to_string().contains("Unsupported"),
        "sign_jws('ES256') is unsupported: {err}"
    );

    // verify_jws: no ES256 verification arm either — even a well-formed
    // JWS is refused before any signature bytes are examined.
    for alg in ["es256", "ecdsa", "ES256"] {
        let err = verify_jws(&jws, &es_keys.a2a_public_key, alg)
            .expect_err("ES256 JWS verification must stay unavailable");
        assert!(
            err.to_string()
                .contains("Unsupported JWS verification algorithm"),
            "verify_jws('{alg}') names the ES256 wall: {err}"
        );
    }
}

/// Source-scan guardrail (accepted repo pattern — see
/// `binding-core/tests/agreement_v2_json.rs::SIMPLE_WRAPPER_SRC`): the raw
/// ES256 signing helpers stay `pub(crate)`. Only the named, scope-checked
/// exporters may reach them; there is no public arbitrary-payload ES256
/// signing surface.
#[test]
fn compatibility_es256_signing_helpers_are_not_public() {
    const ES256_SRC: &str = include_str!("../src/crypt/es256.rs");
    const AP2_SRC: &str = include_str!("../src/compatibility/ap2.rs");
    const VC_SRC: &str = include_str!("../src/compatibility/vc.rs");

    for (src, helper, file) in [
        (ES256_SRC, "sign_es256_jose", "crypt/es256.rs"),
        // Issue 014: keygen is crate-internal too — only the in-crate
        // keystore and the A2A keygen carve-out may mint ES256 key material.
        (ES256_SRC, "generate_es256_keypair", "crypt/es256.rs"),
        (AP2_SRC, "build_ap2_detached_jws", "compatibility/ap2.rs"),
        (VC_SRC, "build_ecdsa_jcs_2019_proof", "compatibility/vc.rs"),
    ] {
        assert!(
            src.contains(&format!("pub(crate) fn {helper}")),
            "{file}: '{helper}' must exist and stay pub(crate)"
        );
        assert!(
            !src.contains(&format!("pub fn {helper}")),
            "{file}: '{helper}' must NOT be public API"
        );
    }

    // The helpers that DO stay public (verify_es256_jose + the encoding
    // utilities) are a documented, sanctioned surface: verification and
    // encoding only, no signing, no keygen. The module docs must carry the
    // sanction marker explaining why they are public.
    assert!(
        ES256_SRC.contains("SANCTIONED PUBLIC SURFACE"),
        "crypt/es256.rs: module docs must carry the 'SANCTIONED PUBLIC SURFACE' \
         marker documenting why the verification/encoding helpers are public"
    );
    assert!(
        ES256_SRC.contains("pub fn verify_es256_jose"),
        "crypt/es256.rs: 'verify_es256_jose' is the sanctioned public verify \
         utility (integration tests + downstream verifiers depend on it)"
    );
}
