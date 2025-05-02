mod utils;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::crypt::KeyManager;
use jacs::crypt::aes_encrypt::decrypt_private_key;
use secrecy::ExposeSecret;
use std::fs;

// fn set_enc_to_pq() {
//     unsafe {
//         env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "test-pq-private.pem");
//         env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "test-pq-public.pem");
//         env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq-dilithium");
//     }
// }

fn get_pq_config() -> String {
    let fixtures_dir = utils::find_fixtures_dir();
    format!("{}/raw/pq.jacs.config.json", fixtures_dir.display())
}

#[test]
#[ignore]
fn test_pq_create() {
    let fixtures_dir = utils::find_fixtures_dir();
    // set_enc_to_pq();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    agent.load_by_config(get_pq_config()).unwrap();
    let json_data = fs::read_to_string(format!("{}/raw/myagent.new.json", fixtures_dir.display()))
        .expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);
    //set_enc_to_pq();
    // does this modify the agent sig?
    agent.generate_keys().expect("Reason");
}

#[test]
fn test_pq_create_and_verify_signature() {
    let fixtures_dir = utils::find_fixtures_dir();
    // set_enc_to_pq();
    utils::set_min_test_env_vars();

    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    agent.load_by_config(get_pq_config()).unwrap();
    let json_data = fs::read_to_string(format!("{}/raw/myagent.new.json", fixtures_dir.display()))
        .expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);
    println!("Agent result right after loading: {}", result.unwrap());

    println!(
        "Agent state right after loading: {}",
        if agent.get_private_key().is_ok() {
            "has private key"
        } else {
            "no private key"
        }
    );
    println!("Current directory: {:?}", std::env::current_dir().unwrap());
    println!("Expected key directories:");
    if let Some(config) = agent.config.as_ref() {
        println!("  Config key dir: {:?}", config.jacs_key_directory());
        println!(
            "  Config key filename: {:?}",
            config.jacs_agent_private_key_filename()
        );

        // Check if the file exists at the expected path
        let full_key_path = format!(
            "{}/{}",
            config
                .jacs_key_directory()
                .as_ref()
                .unwrap_or(&"".to_string()),
            config
                .jacs_agent_private_key_filename()
                .as_ref()
                .unwrap_or(&"".to_string())
        );
        println!("  Full key path: {}", full_key_path);
        println!(
            "  Key exists: {}",
            std::path::Path::new(&full_key_path).exists()
        );
    }

    // Try generating the key first:
    agent.generate_keys().expect("Key generation failed");
    println!(
        "After generating keys: {}",
        if agent.get_private_key().is_ok() {
            "has private key"
        } else {
            "no private key"
        }
    );

    println!("Agent configuration: {:#?}", agent.config);

    let private = agent.get_private_key().unwrap();
    let public = agent.get_public_key().unwrap();
    let binding = agent.get_private_key().unwrap();
    let borrowed_key = binding.expose_secret();
    let key_vec = decrypt_private_key(borrowed_key).expect("Failed to decrypt key");
    println!(
        "loaded keys {} {} ",
        std::str::from_utf8(&key_vec).expect("Failed to convert bytes to string"),
        std::str::from_utf8(&public).expect("Failed to convert bytes to string")
    );
}
