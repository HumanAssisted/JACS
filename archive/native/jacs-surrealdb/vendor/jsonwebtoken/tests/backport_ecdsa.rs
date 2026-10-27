//! Independent wire-format regression tests for the JACS source backport.
//! Public verification vectors are RFC 6979 Appendix A.2.5 / A.2.6, SHA-256
//! and SHA-384 signatures of `sample`. No signing implementation under test
//! produces these expected signatures. Both RFC signatures have high S; their
//! low-S counterparts use the published curve order minus S.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, crypto::verify};

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn check_rfc_vector(algorithm: Algorithm, x: &str, y: &str, r: &str, high_s: &str, low_s: &str) {
    let key = DecodingKey::from_ec_components(
        &URL_SAFE_NO_PAD.encode(hex(x)),
        &URL_SAFE_NO_PAD.encode(hex(y)),
    )
    .unwrap();
    for s in [high_s, low_s] {
        let mut signature = hex(r);
        signature.extend(hex(s));
        let encoded = URL_SAFE_NO_PAD.encode(&signature);
        assert!(verify(&encoded, b"sample", &key, algorithm).unwrap());
        assert!(!verify(&encoded, b"tampered", &key, algorithm).unwrap());
        signature[0] ^= 1;
        assert!(
            !verify(
                &URL_SAFE_NO_PAD.encode(&signature),
                b"sample",
                &key,
                algorithm
            )
            .unwrap()
        );
    }
    let width = hex(r).len() * 2;
    for size in [0, width - 1, width + 1] {
        assert!(
            !verify(
                &URL_SAFE_NO_PAD.encode(vec![0_u8; size]),
                b"sample",
                &key,
                algorithm
            )
            .unwrap()
        );
    }
}

#[test]
fn rfc6979_es256_accepts_both_s_forms_and_rejects_invalid_signatures() {
    check_rfc_vector(
        Algorithm::ES256,
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
    );
}

#[test]
fn rfc6979_es384_accepts_both_s_forms_and_rejects_invalid_signatures() {
    check_rfc_vector(
        Algorithm::ES384,
        "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
        "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
        "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
        "6610b514ea0e87315e01bf24d9fcec70ecf18bf5e69dbad9a727ea302393848fb4f04c6cd0423fdc7169525094629eab",
    );
}

#[cfg(feature = "use_pem")]
#[test]
fn signer_retains_fixed_width_jws_signatures() {
    use jsonwebtoken::{EncodingKey, crypto::sign};
    for (algorithm, private_key, public_key, width) in [
        (
            Algorithm::ES256,
            include_bytes!("ecdsa/private_ecdsa_key.pem").as_slice(),
            include_bytes!("ecdsa/public_ecdsa_key.pem").as_slice(),
            64,
        ),
        (
            Algorithm::ES384,
            include_bytes!("ecdsa/private_jwtio_pkcs8.pem").as_slice(),
            include_bytes!("ecdsa/public_jwtio.pem").as_slice(),
            96,
        ),
    ] {
        let signature = sign(
            b"wire format",
            &EncodingKey::from_ec_pem(private_key).unwrap(),
            algorithm,
        )
        .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&signature).unwrap().len(), width);
        assert!(
            verify(
                &signature,
                b"wire format",
                &DecodingKey::from_ec_pem(public_key).unwrap(),
                algorithm
            )
            .unwrap()
        );
    }
}

#[cfg(feature = "use_pem")]
#[test]
fn es384_jwk_extracts_expected_uncompressed_coordinates() {
    use jsonwebtoken::{EncodingKey, jwk::Jwk};
    // Coordinates independently decoded from the upstream public_jwtio.pem
    // fixture using OpenSSL, not computed by the RustCrypto implementation.
    let key = EncodingKey::from_ec_pem(include_bytes!("ecdsa/private_jwtio_pkcs8.pem")).unwrap();
    let actual =
        serde_json::to_value(Jwk::from_encoding_key(&key, Algorithm::ES384).unwrap()).unwrap();
    assert_eq!(
        actual,
        serde_json::json!({
            "kty": "EC", "crv": "P-384", "alg": "ES384",
            "x": URL_SAFE_NO_PAD.encode(hex("0b5b964978f6733083c0c4cb595e41166c3174ce8f5fda7e3e4f587fdac87f7ef89b95cfd54f2aefd74184b488b9aa23")),
            "y": URL_SAFE_NO_PAD.encode(hex("b2f393dfd51470f2513920f516a60bb9e774ad78a8a088a2d43de3696ea9986549161a1dcc2df5732e6c7ce628b6bcc5")),
        })
    );
}
