//! Portable request-auth-v2 must be byte-for-byte identical to native JACS.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs_core::{DetachedSigner, Ed25519DalekSigner};

#[test]
fn portable_and_native_request_auth_have_identical_wire_bytes_and_verify_both_directions() {
    let signer = Ed25519DalekSigner::generate().unwrap();
    let key = signer.public_key();
    let key_id = "portable-agent:portable-version";
    let url = "https://HAI.EXAMPLE:443/api/v1/link/session?x=a%2Fb&y=2";
    let body = b"{\"ciphertext\":\"exact-body\"}";
    let hash = jacs::crypt::hash::hash_public_key(key);
    assert_eq!(hash, jacs_core::verify::legacy_public_key_hash(key));
    let native = jacs::protocol::build_request_auth_header_with_signer(
        key_id,
        "ring-Ed25519",
        &hash,
        "POST",
        url,
        body,
        "hai.ai",
        |message| {
            signer
                .sign(message.as_bytes())
                .map(|bytes| STANDARD.encode(bytes))
                .map_err(Into::into)
        },
    )
    .unwrap();
    let claims = jacs::protocol::inspect_unverified_request_auth_header(&native).unwrap();
    let portable = jacs_core::request_auth::build_request_auth_header_with_signer_at(
        key_id,
        "ring-Ed25519",
        &hash,
        "POST",
        url,
        body,
        "hai.ai",
        claims.issued_at,
        &claims.nonce,
        |message| {
            signer
                .sign(message.as_bytes())
                .map(|bytes| STANDARD.encode(bytes))
        },
    )
    .unwrap();
    assert_eq!(native, portable);
    jacs::protocol::verify_request_auth_header_with_trusted_key_without_replay(
        &portable, key, key_id, "POST", url, body, "hai.ai", 60,
    )
    .unwrap();
    jacs_core::request_auth::verify_request_auth_header_with_trusted_key_without_replay(
        &native,
        key,
        key_id,
        "POST",
        url,
        body,
        "hai.ai",
        60,
        claims.issued_at,
    )
    .unwrap();
}
