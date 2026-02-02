use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
mod utils;

use jacs::crypt::hash::hash_public_key;
use jacs::crypt::hash::hash_string as jacs_hash_string;
use utils::{fixture_path, load_local_document, load_test_agent_one};

#[test]
fn test_key_hashing() {
    // cargo test   --test key_tests -- --nocapture
    let public_key_with_newline: Vec<u8> =
        std::fs::read(fixture_path("public_key_with_newline.pem")).unwrap();
    let public_key_no_newline: Vec<u8> =
        std::fs::read(fixture_path("public_key_no_newline.pem")).unwrap();

    let hardcoded = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqXxe+VRMQROrxX6i+1xh
nvF6ZNE/zNJzLAUbNdTQte1mTCmCUyI8+XQXuC0JoetfvZm71/wEQe5F8vNONyv4
g3iHpBa0d4eEtlvcD8nqdNFEaSfT4cuBVBBwyOM6ZPSEFrxAV4TmoqeI3GXarls2
X+HQW3TBTcYAq7yGS5kcUbzYsQvqR0CjJ5R1JmtlSODvv42EXY9QYsZCJ+QPPEPH
SFWM9uFUP5H8VQK2aTt0ZWWDO+0Rc2we3RdapfWNpftSqTm8EIUHYxbvjpMF2xMT
YxQPCIM8ChqDZHfKf7VgHC9MyLdyg9CRlfOkz493ubdj/MrayVooZbn1T3pn7Ggt
P0fcckCPROdXOSlgMAaCG+//wGM/v/1jjEa5Wb5OMzahZvfFCzXujSgBd37I7MoN
d/6Zl2SKGrehc2P6YlOvf5tI2bhI/m8AnQDdNgdDjzBAVYPw7G/7gEiqeyNHHOb9
5h01nV7URKrB5iJnZoJC8g1GV5CgDlAB04S3PF8J2Cy+7pyG866D9gCm+1anL/nM
OAK/sL2gdG/+sgqthGFss9NQvmAxqz1TMKzrPQOxE98SmErA7VdhhnTImT35BtqQ
Jsiq8X4NITPf5LMB6vX08XQPaPuDjku2NGMi0ZF0MKPsODreGHnWVRHUe855IMP/
hCmTebk/ToIKWZ+YeOMbi38CAwEAAQ==
-----END PUBLIC KEY-----
"
    .to_string();

    let agent = load_test_agent_one();
    let agent_one_public_key = agent.get_public_key().unwrap();

    let _exepected_hash = "8878ef8b8eae9420475f692f75bce9b6a0512c4d91e4674ae21330394539c5e6";
    let _new_expected_hash = "ce3d294bafee5c388be88f74ad8d8e0054e390964caacc2955c42179638d6df8";

    let _exepected_hash_from_file =
        load_local_document(&fixture_path("public_key_expected_hash.txt").to_string_lossy().to_string()).unwrap();

    // hash
    let public_key_with_newline_hash =
        jacs_hash_string(&String::from_utf8(public_key_with_newline.to_vec()).unwrap());
    let public_key_no_newline_hash =
        jacs_hash_string(&String::from_utf8(public_key_no_newline.to_vec()).unwrap());

    println!(
        "public_key_with_newline_hash {} \n public_key_no_newline_hash {}",
        public_key_with_newline_hash, public_key_no_newline_hash
    );

    let public_key_hash_from_utf8 =
        jacs_hash_string(&String::from_utf8(public_key_with_newline.clone()).unwrap());
    let public_key_hash_from_utf8nnl =
        jacs_hash_string(&String::from_utf8(public_key_no_newline).unwrap());

    println!(
        "public_key_hash_from_utf8 {} \n public_key_hash_from_utf8nnl {}",
        public_key_hash_from_utf8, public_key_hash_from_utf8nnl
    );

    let hardocded_hash = jacs_hash_string(&hardcoded);
    println!("hardocded_hash {}  ", hardocded_hash,);

    let hardcoded_hash_as_vec: Vec<u8> = hardcoded.clone().into_bytes();
    let hardocded_hash2 =
        jacs_hash_string(&String::from_utf8(hardcoded_hash_as_vec.clone()).unwrap());
    println!("hardocded_hash2 {}  ", hardocded_hash2,);

    println!(
        "hardcoded_hash_as_vec  hash_public_key {}  ",
        hash_public_key(hardcoded_hash_as_vec)
    );

    println!(
        "agent_one_public_key  hash_public_key {}  \n {:?}",
        hash_public_key(agent_one_public_key.clone()),
        agent_one_public_key
    );

    let (same, add, remove) = agent.diff_strings(
        &hardcoded,
        &String::from_utf8(agent_one_public_key.clone()).unwrap(),
    );

    println!("same\n{}\nadd\n{}\nremove\n{}", same, add, remove);
    println!(
        "len 1 {} - len 2 {} - len 3 {}",
        hardcoded.len(),
        String::from_utf8(public_key_with_newline.clone())
            .unwrap()
            .len(),
        String::from_utf8(agent_one_public_key.clone())
            .unwrap()
            .len()
    );

    //  for (i, (c1, c2)) in hardcoded.chars().zip(String::from_utf8(agent_one_public_key.clone()).unwrap().chars()).enumerate() {
    //     if c1 != c2 {
    //         println!("Difference found at index {}: '{}' vs '{}'", i, c1, c2);
    //     }
    // }

    // // Check if there are any trailing characters in either string
    // if hardcoded.len() > agent_one_public_key.len() {
    //     println!("Hardcoded string has extra characters: '{}'", &hardcoded[agent_one_public_key.len()..]);
    // } else if agent_one_public_key.len() > hardcoded.len() {
    //     println!("Agent public key has extra characters: '{}'", &String::from_utf8(agent_one_public_key.clone()).unwrap()[hardcoded.len()..]);
    // }

    // let public_key_string = String::from_utf8(public_key_with_newline.to_vec()).expect("Invalid UTF-8");
    // let public_key_rehash2 = jacs_hash_string(&public_key_with_newline);
    // let public_key_string_lossy = String::from_utf8_lossy(public_key_with_newline).to_string();
    // let public_key_rehash3 = jacs_hash_string(&public_key_with_newline);

    // let public_key_string_nnl = String::from_utf8(public_key_no_newline.to_vec()).expect("Invalid UTF-8");
    // let public_key_rehash2_nnl = jacs_hash_string(&public_key_no_newline);
    // let public_key_string_lossy_nnl = String::from_utf8_lossy(public_key_no_newline).to_string();
    // let public_key_rehash3_nnl = jacs_hash_string(&public_key_no_newline);
}
