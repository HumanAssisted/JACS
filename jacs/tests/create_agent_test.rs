mod utils;
use serial_test::serial;
use utils::{create_ring_test_agent, read_new_agent_fixture, read_raw_fixture};

#[test]
#[serial(jacs_env)]
fn test_validate_agent_creation() {
    // RUST_BACKTRACE=1 cargo test create_agent_tests -- --test test_validate_agent_creation
    let mut agent = create_ring_test_agent().expect("Failed to create agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
    let result = agent.create_agent_and_load(&json_data, true, None);

    let _ = match result {
        Ok(_) => Ok(result),
        Err(error) => Err({
            println!("{}", error);
            assert!(false);
        }),
    };
    // agent.save();

    println!("New Agent Created\n\n\n {} ", agent);

    let json_data =
        read_raw_fixture("mysecondagent.new.json").expect("Failed to read second agent fixture");
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
#[serial(jacs_env)]
fn test_validate_single_agent_creation() {
    let mut agent = create_ring_test_agent().expect("Failed to create agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
    let result = agent.create_agent_and_load(&json_data, true, None);

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
#[serial(jacs_env)]
fn test_validate_agent_creation_save_and_load() {
    let mut agent = create_ring_test_agent().expect("Failed to create agent");
    let json_data = read_new_agent_fixture().expect("Failed to read agent fixture");
    let result = agent.create_agent_and_load(&json_data, true, None);

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
