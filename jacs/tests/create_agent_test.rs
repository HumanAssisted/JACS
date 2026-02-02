use jacs::agent::loaders::FileLoader;
mod utils;
use utils::{create_agent_v1, read_new_agent_fixture, read_raw_fixture, set_min_test_env_vars};

#[test]
fn test_validate_agent_creation() {
    set_min_test_env_vars();
    // RUST_BACKTRACE=1 cargo test create_agent_tests -- --test test_validate_agent_creation
    let mut agent = create_agent_v1().expect("Failed to create agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
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
    let json_data = read_raw_fixture("mysecondagent.new.json").expect("Failed to read second agent fixture");
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
    set_min_test_env_vars();
    let mut agent = create_agent_v1().expect("Failed to create agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
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
    set_min_test_env_vars();
    let mut agent = create_agent_v1().expect("Failed to create agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
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
