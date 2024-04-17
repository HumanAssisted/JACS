use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
mod utils;

use jacs::crypt::hash::hash_string as jacs_hash_string;
use utils::{load_local_document, load_test_agent_one, load_test_agent_two};

#[test]
fn test_key_hashing() {
    // cargo test   --test key_tests -- --nocapture
    let public_key_with_newline =
        std::fs::read(&"tests/fixtures/public_key_with_newline.pem".to_string()).unwrap();
    let public_key_no_newline =
        std::fs::read(&"tests/fixtures/public_key_no_newline.pem".to_string()).unwrap();

    let exepected_hash = "8878ef8b8eae9420475f692f75bce9b6a0512c4d91e4674ae21330394539c5e6";
    let exepected_hash_from_file =
        load_local_document(&"tests/fixtures/public_key_expected_hash.txt".to_string()).unwrap();

    // hash
    let public_key_with_newline_hash =
        jacs_hash_string(&String::from_utf8(public_key_with_newline.clone()).unwrap());
    let public_key_no_newline_hash =
        jacs_hash_string(&String::from_utf8(public_key_no_newline.clone()).unwrap());

    println!(
        "public_key_with_newline_hash {} \n public_key_no_newline_hash {}",
        public_key_with_newline_hash, public_key_no_newline_hash
    );

    let public_key_hash_from_utf8 =
        jacs_hash_string(&String::from_utf8(public_key_with_newline).unwrap());
    let public_key_hash_from_utf8nnl =
        jacs_hash_string(&String::from_utf8(public_key_no_newline).unwrap());

    println!(
        "public_key_hash_from_utf8 {} \n public_key_hash_from_utf8nnl {}",
        public_key_hash_from_utf8, public_key_hash_from_utf8nnl
    );

    // let public_key_string = String::from_utf8(public_key_with_newline.to_vec()).expect("Invalid UTF-8");
    // let public_key_rehash2 = jacs_hash_string(&public_key_with_newline);
    // let public_key_string_lossy = String::from_utf8_lossy(public_key_with_newline).to_string();
    // let public_key_rehash3 = jacs_hash_string(&public_key_with_newline);

    // let public_key_string_nnl = String::from_utf8(public_key_no_newline.to_vec()).expect("Invalid UTF-8");
    // let public_key_rehash2_nnl = jacs_hash_string(&public_key_no_newline);
    // let public_key_string_lossy_nnl = String::from_utf8_lossy(public_key_no_newline).to_string();
    // let public_key_rehash3_nnl = jacs_hash_string(&public_key_no_newline);
}
