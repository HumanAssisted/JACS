use std::fs;

#[test]
fn test_validate_agent_json() {
    let json_data = fs::read_to_string("examples/myagent.json");

    match json_data {
        Ok(data) => {
            println!("testing data {}", data);
            let result = jacs::validate_agent(&data, "v1");
            assert!(
                result.is_ok(),
                "Failed to validate myagent.json: {}",
                result.unwrap_err()
            );
        }
        Err(e) => {
            panic!("Failed to read 'examples/myagent.json': {}", e);
        }
    }
}

#[test]
fn test_validate_agent_json_raw() {
    let json_data = r#"{
      "id": "agent123",
      "name": "Agent Smith",
      "role": "Field Agent"
    }"#;

    println!("testing data {}", json_data);
    let result = jacs::validate_agent(&json_data, "v1");
    assert!(
        !result.is_ok(),
        "Correctly failed to validate myagent.json: {}",
        result.unwrap_err()
    );
}

#[test]
fn test_money_and_porshe_json() {
    let mut json_data = fs::read_to_string("examples/mymoney.json");

    match json_data {
        Ok(data) => {
            println!("testing data {}", data);
            let result = jacs::validate_resource(&data, "v1");
            assert!(
                result.is_ok(),
                "Failed to validate mymoney.json: {}",
                result.unwrap_err()
            );
        }
        Err(e) => {
            panic!("Failed to read 'examples/myagent.json': {}", e);
        }
    }

    json_data = fs::read_to_string("examples/mycar.json");
    match json_data {
        Ok(data) => {
            println!("testing data {}", data);
            let result = jacs::validate_resource(&data, "v1");
            assert!(
                result.is_ok(),
                "Failed to validate mycar.json: {}",
                result.unwrap_err()
            );
        }
        Err(e) => {
            panic!("Failed to read 'examples/mycar.json': {}", e);
        }
    }
}
