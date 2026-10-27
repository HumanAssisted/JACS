//! Pure ML-DSA-87 JOSE primitives (RFC 9964, RFC 7515 and RFC 7638).
//!
//! These sign the JWS signing input directly with an empty FIPS 204 context.
//! They do not sign a JACS envelope or prehash, resolve keys, or establish trust.

use crate::{CoreError, DetachedSigner, Pq2025Signer};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const ML_DSA_87: &str = "ML-DSA-87";

/// Export the raw root public key using RFC 9964's algorithm key pair JWK.
/// The stable `kid` is its SHA-256 JWK thumbprint (including `alg`).
pub fn mldsa87_public_jwk(public_key: &[u8]) -> Result<Value, CoreError> {
    if public_key.len() != crate::sign::ML_DSA_87_PUBLIC_KEY_SIZE {
        return Err(CoreError::MalformedKey(
            "ML-DSA-87 public key must be 2592 bytes".into(),
        ));
    }
    let mut jwk =
        json!({"alg": ML_DSA_87, "kty": "AKP", "pub": URL_SAFE_NO_PAD.encode(public_key)});
    let canonical = crate::canonical::canonicalize_json_try(&jwk)?;
    jwk["kid"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())));
    jwk["use"] = json!("sig");
    Ok(jwk)
}

/// Validate a public ML-DSA-87 AKP JWK; private material is never accepted.
/// Optional JOSE usage restrictions must authorize signature verification.
pub fn mldsa87_public_key(jwk: &Value) -> Result<Vec<u8>, CoreError> {
    let invalid = || CoreError::MalformedKey("invalid public ML-DSA-87 AKP JWK".into());
    if jwk["kty"] != "AKP"
        || jwk["alg"] != ML_DSA_87
        || ["priv", "d", "x", "y", "crv", "n", "e"]
            .iter()
            .any(|k| jwk.get(k).is_some())
        || jwk.get("use").is_some_and(|v| v != "sig")
        || jwk.get("key_ops").is_some_and(|v| {
            v.as_array()
                .is_none_or(|ops| ops.as_slice() != [json!("verify")])
        })
    {
        return Err(invalid());
    }
    let key = URL_SAFE_NO_PAD
        .decode(jwk["pub"].as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    if key.len() != crate::sign::ML_DSA_87_PUBLIC_KEY_SIZE {
        return Err(invalid());
    }
    Ok(key)
}

/// Sign arbitrary payload bytes in compact JWS form with the existing PQ key.
/// Applications that require JCS must canonicalize their payload first.
pub fn sign_mldsa87_jws(
    payload: &[u8],
    signer: &Pq2025Signer,
    kid: &str,
) -> Result<String, CoreError> {
    let input = mldsa87_jws_signing_input(payload, kid)?;
    let signature = signer.sign(input.as_bytes())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// Prepare exact signing bytes for a host-managed ML-DSA-87 key.
/// The host signs this ASCII string with pure ML-DSA and an empty context.
pub fn mldsa87_jws_signing_input(payload: &[u8], kid: &str) -> Result<String, CoreError> {
    if kid.is_empty() {
        return Err(CoreError::MalformedDocument("empty JWS kid".into()));
    }
    let header = json!({"alg": ML_DSA_87, "kid": kid, "typ": "JOSE"});
    let header = crate::canonical::canonicalize_json_try(&header)?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

/// Verify this library's compact ML-DSA-87 JWS profile with an explicit key.
/// Only the ordinary base64url payload profile is supported; critical header
/// extensions and unencoded payloads fail closed. No algorithm fallback exists.
pub fn verify_mldsa87_jws(
    jws: &str,
    public_key: &[u8],
    expected_kid: Option<&str>,
) -> Result<Vec<u8>, CoreError> {
    let invalid = || CoreError::MalformedDocument("invalid ML-DSA-87 JWS profile".into());
    let parts: Vec<_> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let header = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| invalid())?;
    let header = crate::strict_json::parse_strict_json_slice(&header)?;
    let object = header.as_object().ok_or_else(invalid)?;
    let kid = header["kid"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(invalid)?;
    if header["alg"] != ML_DSA_87
        || header.get("typ").is_some_and(|typ| typ != "JOSE")
        || object
            .keys()
            .any(|k| !matches!(k.as_str(), "alg" | "typ" | "kid"))
        || expected_kid.is_some_and(|expected| expected != kid)
    {
        return Err(invalid());
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid())?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| invalid())?;
    let input = format!("{}.{}", parts[0], parts[1]);
    Pq2025Signer::verify(public_key, input.as_bytes(), &signature)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::{
        ml_dsa_87,
        traits::{SerDes, Verifier},
    };

    #[test]
    fn verifies_rfc9964_published_mldsa87_vector_and_thumbprint() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/rfc9964-mldsa87-public-vector.json"
        ))
        .unwrap();
        let key = mldsa87_public_key(&fixture["jwk"]).unwrap();
        let exported = mldsa87_public_jwk(&key).unwrap();
        assert_eq!(exported["kid"], fixture["jwk"]["kid"]);
        let payload = verify_mldsa87_jws(
            fixture["jws"].as_str().unwrap(),
            &key,
            fixture["jwk"]["kid"].as_str(),
        )
        .unwrap();
        assert!(!payload.is_empty());
    }

    #[test]
    fn rfc9964_wire_uses_raw_key_and_pure_signing_input() {
        let signer = Pq2025Signer::generate().unwrap();
        let jwk = mldsa87_public_jwk(signer.public_key()).unwrap();
        assert_eq!(mldsa87_public_key(&jwk).unwrap(), signer.public_key());
        assert!(jwk.get("x").is_none());
        let kid = jwk["kid"].as_str().unwrap();
        let payload = br#"{"hello":"world"}"#;
        let jws = sign_mldsa87_jws(payload, &signer, kid).unwrap();
        let parts: Vec<_> = jws.split('.').collect();
        let pk =
            ml_dsa_87::PublicKey::try_from_bytes(signer.public_key().try_into().unwrap()).unwrap();
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig.len(), 4627);
        // Independent primitive check catches accidental JACS prehash/context use.
        assert!(pk.verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &sig.try_into().unwrap(),
            b""
        ));
        assert_eq!(
            verify_mldsa87_jws(&jws, signer.public_key(), Some(kid)).unwrap(),
            payload
        );
        assert!(verify_mldsa87_jws(&jws, signer.public_key(), Some("other")).is_err());
        let wrong = Pq2025Signer::generate().unwrap();
        assert!(verify_mldsa87_jws(&jws, wrong.public_key(), None).is_err());
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(b"tampered"),
            parts[2]
        );
        assert!(verify_mldsa87_jws(&tampered, signer.public_key(), None).is_err());
    }

    #[test]
    fn malformed_jwk_and_jws_headers_fail_closed() {
        let signer = Pq2025Signer::generate().unwrap();
        let jwk = mldsa87_public_jwk(signer.public_key()).unwrap();
        for (field, value) in [
            ("kty", json!("OKP")),
            ("alg", json!("ML-DSA-44")),
            ("pub", json!("AA")),
            ("priv", json!("secret")),
            ("use", json!("enc")),
            ("key_ops", json!(["sign"])),
        ] {
            let mut bad = jwk.clone();
            bad[field] = value;
            assert!(mldsa87_public_key(&bad).is_err(), "{field}");
        }
        for header in [
            r#"{"alg":"ML-DSA-87","alg":"ML-DSA-87","kid":"k","typ":"JOSE"}"#,
            r#"{"alg":"ES256","kid":"k","typ":"JOSE"}"#,
            r#"{"alg":"ML-DSA-87","kid":"k","typ":"JOSE","crit":["future"]}"#,
            r#"{"alg":"ML-DSA-87","kid":"k","typ":"JOSE","b64":false}"#,
        ] {
            let input = format!("{}.eA", URL_SAFE_NO_PAD.encode(header));
            let signed = format!(
                "{input}.{}",
                URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes()).unwrap())
            );
            assert!(verify_mldsa87_jws(&signed, signer.public_key(), None).is_err());
        }
    }
}
