use std::fs;

#[test]
fn test_validate_agent_json() {
    let json_data = fs::read_to_string("examples/myagent.json").unwrap();
    let result = jacs::validate_agent_json(&json_data);
    assert!(result.is_ok(), "Failed to validate myagent.json");
}