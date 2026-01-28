use jacs::agent::loaders::FileLoader;
use std::fs;
mod utils;

#[test]
fn test_validate_agent_creation() {
    utils::set_min_test_env_vars();
    // RUST_BACKTRACE=1 cargo test create_agent_tests -- --test test_validate_agent_creation
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    let json_data = fs::read_to_string("./tests/fixtures/raw/myagent.new.json").expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("{}", error);
            assert!(false);
        }),
    };
    // agent.save();

    println!("New Agent Created\n\n\n {} ", agent);
    // switch keys
    let _ = agent.fs_preload_keys(
        &"agent-two.private.pem".to_string(),
        &"agent-two.public.pem".to_string(),
        Some("RSA-PSS".to_string()),
    );
    let json_data =
        fs::read_to_string("./tests/fixtures/raw/mysecondagent.new.json").expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("{}", error);
            assert!(false);
        }),
    };

    println!("New Agent2 Created\n\n\n {} ", agent);
    // let _ = agent.save();
}

#[test]
fn test_validate_single_agent_creation() {
    utils::set_min_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    let json_data = fs::read_to_string("./tests/fixtures/raw/myagent.new.json").expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("{}", error);
            assert!(false);
        }),
    };

    println!("New Agent Created\n\n\n {} ", agent);
}

#[test]
fn test_validate_agent_creation_save_and_load() {
    utils::set_min_test_env_vars();
    let agent_version = "v1".to_string();
    let header_version = "v1".to_string();
    let signature_version = "v1".to_string();
    let mut agent =
        jacs::agent::Agent::new(&agent_version, &header_version, &signature_version).unwrap();
    let json_data = fs::read_to_string("./tests/fixtures/raw/myagent.new.json").expect("REASON");
    let result = agent.create_agent_and_load(&json_data, false, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("{}", error);
            assert!(false);
        }),
    };

    println!(
        "test_validate_agent_creation_save_and_load Agent Created\n\n\n {} ",
        agent
    );

    // agent.save();
}
