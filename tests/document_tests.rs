mod utils;
use utils::load_test_agent_one;

#[test]
fn test_load_agent_json() {
    // cargo test   --test schema_tests -- --nocapture
    let agent = load_test_agent_one();
}
