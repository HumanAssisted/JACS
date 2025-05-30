use jacs::agent::loaders::FileLoader;
use secrecy::ExposeSecret;
mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use jacs::crypt::aes_encrypt::decrypt_private_key;
use utils::load_test_agent_one;

#[test]
#[ignore]
fn test_rsa_create() {
    let mut agent = load_test_agent_one();
    agent.generate_keys().expect("Reason");
}

#[test]
#[ignore]
fn test_rsa_save_encrypted() {
    let mut agent = load_test_agent_one();
    agent.fs_save_keys().expect("Reason");
}

#[test]
fn test_rsa_create_and_verify_signature() {
    let agent = load_test_agent_one();
    let _private = agent.get_private_key().unwrap();
    let public = agent.get_public_key().unwrap();

    let binding = agent.get_private_key().unwrap();
    let borrowed_key = binding.expose_secret();
    let key_vec = decrypt_private_key(borrowed_key).expect("Failed to decrypt key");

    println!(
        "loaded keys {} {} ",
        std::str::from_utf8(&key_vec).expect("Failed to convert bytes to string"),
        std::str::from_utf8(&public).expect("Failed to convert bytes to string")
    );

    // // cargo test --test rsa_tests -- test_rsa_create_and_verify_signature
    // let input_str = "JACS is JACKED";
    // let file_path = "./tests/scratch/";
    // let sig = jacs::crypt::rsawrapper::sign_string(file_path, input_str);
    // let signature_base64 = match sig {
    //     Ok(signature) => signature,
    //     Err(err_msg) => {
    //         panic!("Failed to sign string: {}", err_msg);
    //     }
    // };

    // println!("signature was {} for {}", signature_base64, input_str);

    // let verify_result =
    //     jacs::crypt::rsawrapper::verify_string(file_path, input_str, &signature_base64);
    // assert!(
    //     verify_result.is_ok(),
    //     "Signature verification failed: {:?}",
    //     verify_result.err()
    // );
}
