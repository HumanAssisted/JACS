mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use utils::{load_test_agent_one, set_test_env_vars};

#[test]
#[ignore]
fn test_rsa_create() {
    set_test_env_vars();
    let mut agent = load_test_agent_one();
}

#[test]
fn test_rsa_create_and_verify_signature() {
    set_test_env_vars();
    let mut agent = load_test_agent_one();

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
