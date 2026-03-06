use jacs::crypt::hash::{hash_public_key, hash_string};

mod utils;

use utils::fixture_path;

const EXPECTED_RAW_HASH_WITH_TRAILING_NEWLINE: &str =
    "8878ef8b8eae9420475f692f75bce9b6a0512c4d91e4674ae21330394539c5e6";
const EXPECTED_NORMALIZED_PUBLIC_KEY_HASH: &str =
    "2c9cc6361e2003173df86b9c267b3891193319da7fe7c6f42cb0fbe5b30d7c0d";

#[test]
fn hash_string_matches_fixture_golden_value() {
    let public_key_with_newline =
        std::fs::read_to_string(fixture_path("public_key_with_newline.pem")).unwrap();
    let expected_hash =
        std::fs::read_to_string(fixture_path("public_key_expected_hash.txt")).unwrap();

    assert_eq!(
        hash_string(&public_key_with_newline),
        expected_hash.trim(),
        "hash_string() should remain byte-for-byte stable for the fixture input",
    );
    assert_eq!(
        expected_hash.trim(),
        EXPECTED_RAW_HASH_WITH_TRAILING_NEWLINE
    );
}

#[test]
fn hash_public_key_normalizes_equivalent_pem_encodings() {
    let public_key_with_newline =
        std::fs::read_to_string(fixture_path("public_key_with_newline.pem")).unwrap();
    let public_key_no_newline =
        std::fs::read_to_string(fixture_path("public_key_no_newline.pem")).unwrap();

    assert_eq!(
        hash_public_key(public_key_with_newline.as_bytes()),
        EXPECTED_NORMALIZED_PUBLIC_KEY_HASH,
    );
    assert_eq!(
        hash_public_key(public_key_no_newline.as_bytes()),
        EXPECTED_NORMALIZED_PUBLIC_KEY_HASH,
    );
    assert_eq!(
        hash_public_key(public_key_with_newline.as_bytes()),
        hash_public_key(public_key_no_newline.as_bytes()),
        "hash_public_key() should ignore trailing newline differences",
    );
    assert_ne!(
        hash_string(&public_key_with_newline),
        hash_public_key(public_key_with_newline.as_bytes()),
        "raw hashing and public-key hashing should stay intentionally distinct",
    );
}
