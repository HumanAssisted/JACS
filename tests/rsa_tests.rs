use std::env;

fn set_enc_to_rsa() {
    env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "rsa_pss_private.pem");
    env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "rsa_pss_public.pem");
    env::set_var("JACS_AGENT_KEY_ALGORITHM", "RSA-PSS");
}

#[test]
#[ignore]
fn test_rsa_create() {
    set_enc_to_rsa();
    // Test body would be here
}

#[test]
#[ignore]
fn test_rsa_save_encrypted() {
    set_enc_to_rsa();
    // Test body would be here
}

#[test]
fn test_rsa_create_and_verify_signature() {
    set_enc_to_rsa();
    // Test body would be here
}
